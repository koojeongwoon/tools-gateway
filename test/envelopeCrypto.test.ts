import { describe, it, expect } from "vitest";
import { EnvelopeCrypto } from "../src/crypto/envelopeCrypto.js";

describe("EnvelopeCrypto", () => {
  const masterSecret = "test-master-encryption-key-for-vault-1234";
  const crypto = new EnvelopeCrypto(masterSecret);

  it("should encrypt and decrypt plaintext successfully", () => {
    const secretText = "bearer_secret_token_12345!@#$%";
    const encrypted = crypto.encrypt(secretText);

    expect(encrypted.encryptedValue).toBeDefined();
    expect(encrypted.iv).toHaveLength(24); // 12 bytes = 24 hex chars
    expect(encrypted.tag).toHaveLength(32); // 16 bytes = 32 hex chars
    expect(encrypted.encryptedValue).not.toBe(secretText);

    const decrypted = crypto.decrypt(encrypted);
    expect(decrypted).toBe(secretText);
  });

  it("should fail decryption when authentication tag is tampered", () => {
    const encrypted = crypto.encrypt("my_secret");
    const tamperedTag = "00".repeat(16);

    expect(() => {
      crypto.decrypt({ ...encrypted, tag: tamperedTag });
    }).toThrow();
  });
});
