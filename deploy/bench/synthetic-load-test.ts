import { performance } from "node:perf_hooks";

const ENDPOINTS = [
  "/health",
  "/api/data",
  "/api/providers/catalog",
  "/forgot-password",
  "/privacy",
] as const;
const SESSION_COOKIE_PATTERN = /^usage_session=[a-f0-9]{64}$/i;

interface BenchmarkConfiguration {
  baseUrl: URL;
  sessionCookies: string[];
  requestCount: number;
  concurrency: number;
  timeoutMs: number;
}

function parseInteger(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }
  return value;
}

function parseConfiguration(): BenchmarkConfiguration {
  let baseUrl: URL;
  try {
    baseUrl = new URL(process.env["USEMETER_BENCH_URL"] ?? "http://127.0.0.1:3100");
  } catch {
    throw new Error("USEMETER_BENCH_URL must be a valid loopback URL.");
  }
  if (
    baseUrl.protocol !== "http:" ||
    baseUrl.hostname !== "127.0.0.1" ||
    baseUrl.pathname !== "/" ||
    baseUrl.search !== "" ||
    baseUrl.hash !== "" ||
    baseUrl.username !== "" ||
    baseUrl.password !== ""
  ) {
    throw new Error("USEMETER_BENCH_URL must be a plain HTTP 127.0.0.1 origin with no path or credentials.");
  }
  const proxyVariables = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"];
  if (proxyVariables.some(name => Boolean(process.env[name]?.trim()))) {
    throw new Error("Unset HTTP proxy environment variables before running the loopback-only benchmark.");
  }

  const rawCookies = process.env["USEMETER_BENCH_SESSION_COOKIES"];
  if (!rawCookies) {
    throw new Error("USEMETER_BENCH_SESSION_COOKIES must contain at least two synthetic tenant cookies as a JSON array.");
  }
  let parsedCookies: unknown;
  try {
    parsedCookies = JSON.parse(rawCookies);
  } catch {
    throw new Error("USEMETER_BENCH_SESSION_COOKIES must be valid JSON.");
  }
  if (!Array.isArray(parsedCookies) || parsedCookies.length < 2 || parsedCookies.length > 100) {
    throw new Error("Provide between 2 and 100 synthetic tenant session cookies.");
  }
  const sessionCookies: string[] = [];
  for (const cookie of parsedCookies) {
    if (typeof cookie !== "string" || !SESSION_COOKIE_PATTERN.test(cookie)) {
      throw new Error("Provide only usage_session cookies from synthetic tenant accounts.");
    }
    sessionCookies.push(cookie);
  }
  if (new Set(sessionCookies).size < 2) {
    throw new Error("Provide at least two distinct usage_session cookies from synthetic tenant accounts.");
  }

  const requestCount = parseInteger("USEMETER_BENCH_REQUESTS", 1_000, 50, 100_000);
  const concurrency = parseInteger("USEMETER_BENCH_CONCURRENCY", 50, 50, 100);
  if (requestCount < concurrency) {
    throw new Error("USEMETER_BENCH_REQUESTS must be at least the concurrency level.");
  }
  return {
    baseUrl,
    sessionCookies,
    requestCount,
    concurrency,
    timeoutMs: parseInteger("USEMETER_BENCH_TIMEOUT_MS", 10_000, 1_000, 120_000),
  };
}

function readUserId(value: unknown): string | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value) || !("user" in value)) {
    return undefined;
  }
  const user = value.user;
  if (typeof user !== "object" || user === null || Array.isArray(user) || !("id" in user)) {
    return undefined;
  }
  return typeof user.id === "string" && user.id.length > 0 ? user.id : undefined;
}

async function verifySyntheticTenants(configuration: BenchmarkConfiguration): Promise<number> {
  const userIds = await Promise.all(configuration.sessionCookies.map(async cookie => {
    const response = await fetch(new URL("/api/auth/me", configuration.baseUrl), {
      headers: { Cookie: cookie },
      redirect: "manual",
      signal: AbortSignal.timeout(configuration.timeoutMs),
    });
    if (!response.ok) throw new Error("A supplied synthetic session is not authenticated.");
    const userId = readUserId(await response.json());
    if (!userId) throw new Error("Could not identify a supplied synthetic session.");
    return userId;
  }));
  const tenantCount = new Set(userIds).size;
  if (tenantCount < 2) throw new Error("Sessions must belong to at least two distinct synthetic tenant accounts.");
  return tenantCount;
}

function percentile(sortedValues: number[], fraction: number): number {
  const index = Math.max(0, Math.ceil(sortedValues.length * fraction) - 1);
  return sortedValues[index] ?? 0;
}


async function runBenchmark(configuration: BenchmarkConfiguration, tenantCount: number): Promise<void> {
  const latenciesMs: number[] = [];
  const statusCounts: Record<string, number> = {};
  let transportErrors = 0;
  let nextRequest = 0;
  const startRssBytes = process.memoryUsage().rss;
  let peakRssBytes = startRssBytes;
  const startedAt = performance.now();
  const rssSampler = setInterval(() => {
    peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
  }, 100);

  const worker = async (): Promise<void> => {
    while (true) {
      const requestIndex = nextRequest++;
      if (requestIndex >= configuration.requestCount) return;
      const endpoint = ENDPOINTS[requestIndex % ENDPOINTS.length]!;
      const cookie = configuration.sessionCookies[requestIndex % configuration.sessionCookies.length]!;
      const requestStartedAt = performance.now();
      try {
        const response = await fetch(new URL(endpoint, configuration.baseUrl), {
          headers: { Cookie: cookie },
          redirect: "manual",
          signal: AbortSignal.timeout(configuration.timeoutMs),
        });
        await response.arrayBuffer();
        statusCounts[String(response.status)] = (statusCounts[String(response.status)] ?? 0) + 1;
      } catch {
        transportErrors++;
      } finally {
        latenciesMs.push(performance.now() - requestStartedAt);
        peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
      }
    }
  };

  try {
    await Promise.all(Array.from({ length: configuration.concurrency }, worker));
  } finally {
    clearInterval(rssSampler);
    peakRssBytes = Math.max(peakRssBytes, process.memoryUsage().rss);
  }

  const durationMs = performance.now() - startedAt;
  const sortedLatencies = latenciesMs.sort((left, right) => left - right);
  const statusErrors = Object.entries(statusCounts)
    .filter(([status]) => Number(status) < 200 || Number(status) >= 300)
    .reduce((count, [, total]) => count + total, 0);
  const totalErrors = transportErrors + statusErrors;
  const endRssBytes = process.memoryUsage().rss;
  const summary = {
    target: configuration.baseUrl.origin,
    syntheticTenants: tenantCount,
    requestCount: configuration.requestCount,
    concurrency: configuration.concurrency,
    durationMs: Number(durationMs.toFixed(2)),
    requestsPerSecond: Number((configuration.requestCount / (durationMs / 1_000)).toFixed(2)),
    latencyMs: {
      p50: Number(percentile(sortedLatencies, 0.50).toFixed(3)),
      p95: Number(percentile(sortedLatencies, 0.95).toFixed(3)),
      p99: Number(percentile(sortedLatencies, 0.99).toFixed(3)),
    },
    errors: totalErrors,
    errorRatePercent: Number(((totalErrors / configuration.requestCount) * 100).toFixed(3)),
    transportErrors,
    statusCounts,
    rssBytes: {
      start: startRssBytes,
      peak: peakRssBytes,
      end: endRssBytes,
      peakGrowth: peakRssBytes - startRssBytes,
      endGrowth: endRssBytes - startRssBytes,
    },
    providerCalls: 0,
    externalNetworkCalls: 0,
  };
  console.log(JSON.stringify(summary));
  if (totalErrors > 0) process.exitCode = 1;
}

async function main(): Promise<void> {
  const configuration = parseConfiguration();
  const tenantCount = await verifySyntheticTenants(configuration);
  await runBenchmark(configuration, tenantCount);
}

if (import.meta.main) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : "Synthetic benchmark failed.");
    process.exitCode = 1;
  });
}
