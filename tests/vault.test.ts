import { describe, expect, test, beforeEach } from 'bun:test';
import { StorageVault } from '../src/core/storage/vault';
import type { StoredCredential } from '../src/types';

let vault: StorageVault;

beforeEach(() => {
  vault = new StorageVault(':memory:');
});

describe('StorageVault', () => {
  test('should update credential label', () => {
    const provider = 'test-provider';
    const accountLabel = 'Old Label';
    const accent = 'default';
    const newLabel = 'New Label';
    const credentialType = 'api_key';
    const secret = 'test-secret';

    const savedCredential = vault.saveCredential({ provider, accountLabel, accent, credentialType, secret });
    const result = vault.updateCredentialLabel(savedCredential.id, newLabel);
    expect(result).toBe(true);

    const updatedCredential = vault.listCredentials().find((c: StoredCredential) => c.id === savedCredential.id);
    expect(updatedCredential?.accountLabel).toBe(newLabel);
  });

  // Add more tests as needed
});