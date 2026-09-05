import { describe, it, expect } from "vitest";
import { loadR2AuditConfig } from "../src/config/r2.js";

describe("R2 Audit Config (R2_ENDPOINT or R2_ACCOUNT_ID + AWS_ keys)", () => {
  it("should support R2_ACCOUNT_ID with standard AWS keys", () => {
    const config = loadR2AuditConfig({
      R2_AUDIT_ENABLED: "true",
      R2_ACCOUNT_ID: "abc123account",
      AWS_ACCESS_KEY_ID: "aws-key-id",
      AWS_SECRET_ACCESS_KEY: "aws-secret-key",
      R2_BUCKET_NAME: "backup",
    });

    expect(config.enabled).toBe(true);
    expect(config.endpoint).toBe("https://abc123account.r2.cloudflarestorage.com");
    expect(config.accessKeyId).toBe("aws-key-id");
    expect(config.secretAccessKey).toBe("aws-secret-key");
    expect(config.bucketName).toBe("backup");
  });

  it("should still support direct R2_ENDPOINT and R2_ACCESS_KEY_ID", () => {
    const config = loadR2AuditConfig({
      R2_AUDIT_ENABLED: "true",
      R2_ENDPOINT: "https://custom.r2.cloudflarestorage.com",
      R2_ACCESS_KEY_ID: "r2-key",
      R2_SECRET_ACCESS_KEY: "r2-secret",
    });

    expect(config.enabled).toBe(true);
    expect(config.endpoint).toBe("https://custom.r2.cloudflarestorage.com");
    expect(config.accessKeyId).toBe("r2-key");
    expect(config.secretAccessKey).toBe("r2-secret");
  });
});
