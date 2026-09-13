import { Database } from "bun:sqlite";
import type { StorageVault } from "./storage/vault";
import type { CredentialType } from "../types";

export interface OmpSyncResult {
  total: number;
  imported: Array<{ id: string; provider: string; accountLabel: string }>;
}

const DEFAULT_OMP_DB_PATH = "${HOME}/dotfiles/omp/.config/omp/agent/agent.db";

interface OmpCredentialRow {
  id: string;
  provider: string;
  credential_type: string;
  data: string;
  identity_key: string | null;
  disabled_cause: string | null;
}

export function syncCredentialsFromOmp(
  vault: StorageVault,
  ompDbPath: string = DEFAULT_OMP_DB_PATH,
): OmpSyncResult {
  let db: Database;
  try {
    db = new Database(ompDbPath, { readonly: true });
  } catch (err) {
    console.warn(`[OMP Sync] OMP agent.db açılamadı (${ompDbPath}):`, err);
    return { total: 0, imported: [] };
  }

  const imported: Array<{ id: string; provider: string; accountLabel: string }> = [];

  try {
    const rows = db.prepare(`
      SELECT id, provider, credential_type, data, identity_key, disabled_cause
      FROM auth_credentials
      WHERE disabled_cause IS NULL OR disabled_cause = 'no'
    `).all() as OmpCredentialRow[];

    for (const r of rows) {
      try {
        // Skip non-LLM MCP OAuth profiles
        if (r.provider.startsWith("mcp_")) continue;

        const d = JSON.parse(r.data) as Record<string, unknown>;
        const secret = String(d["access"] || d["key"] || d["token"] || d["apiKey"] || "");
        if (!secret) continue;

        let label: string | undefined;

        if (r.identity_key) {
          if (r.identity_key.startsWith("email:")) {
            label = r.identity_key.replace(/^email:/, "").split("|")[0];
          } else if (r.identity_key.startsWith("account:")) {
            label = r.identity_key.replace(/^account:/, "");
          }
        }

        if (!label) {
          label = (d["email"] as string) || (d["orgName"] as string) || (d["accountId"] ? `Account ${String(d["accountId"]).slice(0, 8)}` : undefined);
        }

        if (!label) {
          label = `${r.provider} (#${String(r.id)})`;
        }

        // Clean provider name for antigravity
        const providerName = r.provider === "google-antigravity" ? "antigravity" : r.provider;

        // Clean label: remove "Google (" prefix if present
        label = label.replace(/^Google \((.*)\)$/, "$1");

        const credType = (r.credential_type === "oauth" ? "oauth" : "api_key") as CredentialType;

        const saved = vault.saveCredential({
          provider: providerName,
          accountLabel: label,
          credentialType: credType,
          secret,
          metadata: {
            refreshToken: d["refresh"],
            accountId: d["accountId"],
            email: d["email"],
            orgId: d["orgId"],
            projectId: d["projectId"],
            source: "omp-sync",
          },
        });

        imported.push({
          id: saved.id,
          provider: saved.provider,
          accountLabel: saved.accountLabel,
        });
      } catch (err) {
        console.warn(`[OMP Sync] ${r.provider} (${r.id}) ayrıştırma hatası:`, err);
      }
    }
  } finally {
    db.close();
  }

  return {
    total: imported.length,
    imported,
  };
}
