export const CLAUDE_REDIRECT_URI = "http://localhost:54545/callback";
export const GEMINI_CLI_REDIRECT_URI = "http://127.0.0.1:8085/oauth2callback";
export const ZAI_REDIRECT_URI = "http://127.0.0.1:9999/callback";
export const GOOGLE_EMBEDDED_REDIRECT_URI = "http://127.0.0.1:51121/oauth-callback";

export interface ParsedOAuthCallback {
  state: string;
  code?: string;
  providerError?: string;
}

export type ManualOAuthInputOptions =
  | {
      mode: "url";
      redirectUri: string;
      expectedState: string;
      allowCodeHashState?: boolean;
    }
  | { mode: "code" };

export function parseOAuthCallbackParameters(params: URLSearchParams): ParsedOAuthCallback | null {
  const seen = new Set<string>();
  for (const [name] of params) {
    if (seen.has(name)) return null;
    seen.add(name);
  }

  const state = params.get("state");
  const code = params.get("code");
  const providerError = params.get("error");
  if (!state?.trim() || (code !== null && !code.trim()) || (providerError !== null && !providerError.trim())) {
    return null;
  }
  if (code !== null && providerError !== null) return null;
  if (providerError !== null) return { state, providerError };
  if (code === null) return null;
  return { state, code };
}

export function parseOAuthManualInput(
  value: unknown,
  options: ManualOAuthInputOptions,
): ParsedOAuthCallback | null {
  if (typeof value !== "string") return null;
  const input = value.trim();
  if (!input) return null;

  if (options.mode === "code") {
    if (/^https?:\/\//i.test(input) || /[\u0000-\u001F\u007F]/.test(input)) return null;
    return { state: "", code: input };
  }

  if (options.allowCodeHashState) {
    const hash = input.indexOf("#");
    if (
      hash > 0 &&
      hash === input.lastIndexOf("#") &&
      !/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(input.slice(0, hash).trim())
    ) {
      const code = input.slice(0, hash).trim();
      const state = input.slice(hash + 1).trim();
      if (code && state === options.expectedState) return { state, code };
      return null;
    }
  }

  if (
    !input.startsWith(`${options.redirectUri}?`) ||
    input.includes("#") ||
    input.includes("\\") ||
    /[\u0000-\u001F]/.test(input)
  ) return null;
  try {
    const callback = new URL(input);
    const expected = new URL(options.redirectUri);
    if (
      callback.origin !== expected.origin ||
      callback.pathname !== expected.pathname ||
      callback.username ||
      callback.password ||
      callback.hash
    ) {
      return null;
    }
    const parsed = parseOAuthCallbackParameters(callback.searchParams);
    if (!parsed || parsed.state !== options.expectedState) return null;
    return parsed;
  } catch {
    return null;
  }
}
