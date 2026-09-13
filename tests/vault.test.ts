import { describe, expect, it } from "bun:test";
import { decryptSecret, encryptSecret } from "../src/core/crypto";
import { StorageVault } from "../src/core/storage/vault";

describe("Crypto", () => {
  it("encrypts and decrypts secrets symmetrically", () => {
    const secret = "sk-ant-api03-sample-super-secret-key-12345";
    const encrypted = encryptSecret(secret);

    expect(encrypted.ciphertext).not.toBe(secret);
    expect(encrypted.iv.length).toBe(24); // 12 bytes hex
    expect(encrypted.tag.length).toBe(32); // 16 bytes hex

    const decrypted = decryptSecret(encrypted);
    expect(decrypted).toBe(secret);
  });
});

describe("StorageVault", () => {
  it("initializes SQLite in-memory and executes CRUD", () => {
    const vault = new StorageVault(":memory:");
    expect(vault.checkIntegrity()).toBe(true);

    const saved = vault.saveCredential({
      provider: "openrouter",
      accountLabel: "Primary Key",
      credentialType: "api_key",
      secret: "sk-or-v1-my-secret-key",
    });

    expect(saved.id).toBeDefined();
    expect(saved.provider).toBe("openrouter");

    const list = vault.listCredentials("openrouter");
    expect(list.length).toBe(1);
    expect(list[0]?.secret).toBe("sk-or-v1-my-secret-key");
    expect(list[0]?.accountLabel).toBe("Primary Key");

    // Test usage snapshot
    vault.saveUsageSnapshot({
      provider: "openrouter",
      credentialId: saved.id,
      accountLabel: "Primary Key",
      fetchedAt: Date.now(),
      limits: [
        {
          id: "balance",
          label: "Remaining Credits",
          amount: { used: 10, remaining: 40, limit: 50, unit: "usd" },
          status: "ok",
        },
      ],
    });

    const latest = vault.getLatestUsage();
    expect(latest.length).toBe(1);
    expect(latest[0]?.limits[0]?.amount.remaining).toBe(40);

    vault.close();
  });
});
