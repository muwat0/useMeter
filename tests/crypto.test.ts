import { describe, expect, it, beforeEach, afterEach } from "bun:test";
import {
  assertMasterKeyConfigured,
  encryptSecret,
  decryptSecret,
  LEGACY_DEV_MASTER_KEY,
} from "../src/core/crypto";

describe("Production Master Key Enforcement (AUTH-DEFAULT-MASTER-KEY)", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Reset to clean snapshot of original environment before each test
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, originalEnv);
  });

  afterEach(() => {
    // Restore original environment completely after each test
    for (const key of Object.keys(process.env)) {
      if (!(key in originalEnv)) {
        delete process.env[key];
      }
    }
    Object.assign(process.env, originalEnv);
  });

  describe("assertMasterKeyConfigured", () => {
    it("throws when NODE_ENV is production and USAGE_MASTER_KEY is undefined", () => {
      delete process.env["USAGE_MASTER_KEY"];
      process.env["NODE_ENV"] = "production";

      expect(() => assertMasterKeyConfigured()).toThrow(
        "USAGE_MASTER_KEY must be set to a secure, non-default secret in production (NODE_ENV=production)."
      );
    });

    it("throws when NODE_ENV is production and USAGE_MASTER_KEY is empty or whitespace", () => {
      process.env["NODE_ENV"] = "production";

      process.env["USAGE_MASTER_KEY"] = "";
      expect(() => assertMasterKeyConfigured()).toThrow(
        "USAGE_MASTER_KEY must be set to a secure, non-default secret in production"
      );

      process.env["USAGE_MASTER_KEY"] = "   ";
      expect(() => assertMasterKeyConfigured()).toThrow(
        "USAGE_MASTER_KEY must be set to a secure, non-default secret in production"
      );
    });

    it("throws when NODE_ENV is production and USAGE_MASTER_KEY equals legacy fallback", () => {
      process.env["NODE_ENV"] = "production";
      process.env["USAGE_MASTER_KEY"] = LEGACY_DEV_MASTER_KEY;

      expect(() => assertMasterKeyConfigured()).toThrow(
        "USAGE_MASTER_KEY must be set to a secure, non-default secret in production (NODE_ENV=production)."
      );
    });

    it("accepts a non-default USAGE_MASTER_KEY in production", () => {
      process.env["NODE_ENV"] = "production";
      process.env["USAGE_MASTER_KEY"] = "super-secret-production-master-key-32-chars-long";

      expect(() => assertMasterKeyConfigured()).not.toThrow();
    });

    it("permits missing or legacy USAGE_MASTER_KEY in development mode", () => {
      process.env["NODE_ENV"] = "development";
      delete process.env["USAGE_MASTER_KEY"];
      expect(() => assertMasterKeyConfigured()).not.toThrow();

      process.env["USAGE_MASTER_KEY"] = LEGACY_DEV_MASTER_KEY;
      expect(() => assertMasterKeyConfigured()).not.toThrow();
    });

    it("permits custom environment dictionary passed as argument", () => {
      const prodEnvWithoutKey = { NODE_ENV: "production" };
      expect(() => assertMasterKeyConfigured(prodEnvWithoutKey)).toThrow(
        "USAGE_MASTER_KEY must be set to a secure, non-default secret in production"
      );

      const prodEnvWithKey = {
        NODE_ENV: "production",
        USAGE_MASTER_KEY: "prod-key-12345",
      };
      expect(() => assertMasterKeyConfigured(prodEnvWithKey)).not.toThrow();
    });
  });

  describe("encryptSecret / decryptSecret behavior", () => {
    it("fails closed in production if USAGE_MASTER_KEY is not set", () => {
      process.env["NODE_ENV"] = "production";
      delete process.env["USAGE_MASTER_KEY"];

      expect(() => encryptSecret("my-sensitive-token")).toThrow(
        "USAGE_MASTER_KEY must be set to a secure, non-default secret in production"
      );
    });

    it("fails closed in production if USAGE_MASTER_KEY is the legacy fallback", () => {
      process.env["NODE_ENV"] = "production";
      process.env["USAGE_MASTER_KEY"] = LEGACY_DEV_MASTER_KEY;

      expect(() => encryptSecret("my-sensitive-token")).toThrow(
        "USAGE_MASTER_KEY must be set to a secure, non-default secret in production"
      );
    });

    it("encrypts and decrypts with custom key in production", () => {
      process.env["NODE_ENV"] = "production";
      process.env["USAGE_MASTER_KEY"] = "prod-strong-encryption-secret-key-xyz";

      const payload = encryptSecret("my-sensitive-token");
      expect(payload.ciphertext).toBeDefined();
      expect(payload.iv).toHaveLength(24); // 12 bytes = 24 hex chars
      expect(payload.tag).toHaveLength(32); // 16 bytes = 32 hex chars

      const decrypted = decryptSecret(payload);
      expect(decrypted).toBe("my-sensitive-token");
    });

    it("preserves compatibility with legacy fallback key in development mode", () => {
      process.env["NODE_ENV"] = "development";
      delete process.env["USAGE_MASTER_KEY"];

      const payload = encryptSecret("local-dev-credential");
      const decrypted = decryptSecret(payload);
      expect(decrypted).toBe("local-dev-credential");
    });
  });
});
