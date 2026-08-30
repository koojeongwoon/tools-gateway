import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";

export interface EncryptedSecret {
  encryptedValue: string; // hex
  iv: string;             // hex (12 bytes for GCM)
  tag: string;            // hex (16 bytes auth tag)
}

export class EnvelopeCrypto {
  private readonly key: Buffer;

  constructor(masterSecret: string) {
    if (!masterSecret) {
      throw new Error("Master secret is required for EnvelopeCrypto");
    }
    // 마스터 시크릿을 SHA-256 해싱하여 32바이트(256비트) AES 키 생성
    this.key = createHash("sha256").update(masterSecret).digest();
  }

  encrypt(plainText: string): EncryptedSecret {
    const iv = randomBytes(12); // GCM 표준 12바이트 IV
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    
    let encrypted = cipher.update(plainText, "utf8", "hex");
    encrypted += cipher.final("hex");
    const tag = cipher.getAuthTag().toString("hex");

    return {
      encryptedValue: encrypted,
      iv: iv.toString("hex"),
      tag,
    };
  }

  decrypt(encrypted: EncryptedSecret): string {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.key,
      Buffer.from(encrypted.iv, "hex"),
    );
    decipher.setAuthTag(Buffer.from(encrypted.tag, "hex"));

    let decrypted = decipher.update(encrypted.encryptedValue, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  }
}
