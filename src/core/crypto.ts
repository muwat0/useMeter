import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // Standard 96-bit IV for GCM
const SALT = "ai-usage-tracker-fixed-salt-v1";

export const LEGACY_DEV_MASTER_KEY = "default-insecure-dev-master-key-change-in-prod";

export function assertMasterKeyConfigured(env: NodeJS.ProcessEnv = process.env): void {
  const nodeEnv = env["NODE_ENV"];
  const isProduction = nodeEnv === "production";
  const masterSecret = env["USAGE_MASTER_KEY"]?.trim();

  if (isProduction) {
    if (!masterSecret || masterSecret === LEGACY_DEV_MASTER_KEY) {
      throw new Error(
        "USAGE_MASTER_KEY must be set to a secure, non-default secret in production (NODE_ENV=production)."
      );
    }
  }
}

// Resolve 32-byte key from environment or fallback machine seed in non-production
function getMasterKey(): Buffer {
  assertMasterKeyConfigured();
  const masterSecret = process.env["USAGE_MASTER_KEY"]?.trim() || LEGACY_DEV_MASTER_KEY;
  return scryptSync(masterSecret, SALT, 32);
}
export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  tag: string;
}

export function encryptSecret(plaintext: string): EncryptedPayload {
  const key = getMasterKey();
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");

  const tag = cipher.getAuthTag();

  return {
    ciphertext: encrypted,
    iv: iv.toString("hex"),
    tag: tag.toString("hex"),
  };
}

export function decryptSecret(payload: EncryptedPayload): string {
  const key = getMasterKey();
  const iv = Buffer.from(payload.iv, "hex");
  const tag = Buffer.from(payload.tag, "hex");
  const decipher = createDecipheriv(ALGORITHM, key, iv);

  decipher.setAuthTag(tag);

  let decrypted = decipher.update(payload.ciphertext, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

export async function hashPassword(password: string): Promise<string> {
  return Bun.password.hash(password, { algorithm: "argon2id", memoryCost: 65536, timeCost: 2 });
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await Bun.password.verify(password, hash);
  } catch {
    return false;
  }
}

export function generateSessionToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Buffer.from(bytes).toString("hex");
}

export function hashSessionToken(token: string): string {
  return new Bun.CryptoHasher("sha256").update(token).digest("hex");
}
