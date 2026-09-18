import { describe, expect, it, vi } from "vitest";
import { EnsureLocalUserService } from "../src/users/ensureLocalUser.js";

describe("EnsureLocalUserService", () => {
  it("atomically upserts by verified tenant and subject", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ id: "existing-local-id" }] });
    const service = new EnsureLocalUserService({ query } as never, "tenant-a");

    await expect(service.ensureLocalUser({
      tenantId: "tenant-a",
      subject: "iam-user-1",
      email: "user@example.com",
      name: "User",
      userVersion: 2,
    })).resolves.toBe("existing-local-id");

    expect(query).toHaveBeenCalledWith(
      expect.stringContaining("ON CONFLICT (tenant_id, external_provider, external_subject_id)"),
      expect.arrayContaining(["user@example.com", "iam-user-1", "tenant-a", 2]),
    );
  });

  it("rejects another tenant before querying the database", async () => {
    const query = vi.fn();
    const service = new EnsureLocalUserService({ query } as never, "tenant-a");

    await expect(service.ensureLocalUser({
      tenantId: "tenant-b",
      subject: "iam-user-1",
      email: "user@example.com",
      userVersion: 1,
    })).rejects.toThrow("does not belong");
    expect(query).not.toHaveBeenCalled();
  });

  it("does not authenticate an inactive conflicting row", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [] });
    const service = new EnsureLocalUserService({ query } as never, "tenant-a");

    await expect(service.ensureLocalUser({
      tenantId: "tenant-a",
      subject: "iam-user-1",
      email: "user@example.com",
      userVersion: 3,
    })).rejects.toThrow("inactive");
  });
});
