import { createPrivateKey, createPublicKey, sign, type KeyObject } from "node:crypto";
import { open, lstat } from "node:fs/promises";
import { constants } from "node:fs";
import { z } from "zod";
import { canonicalJobJson, JOB_TYPE, jobSchema, type JobTrust, type ManagementJob } from "./contract.js";

const keySchema = z.object({ kid: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/),
  kty: z.literal("OKP"), crv: z.literal("Ed25519"), x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  d: z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict();
export class JobSigner {
  private constructor(private readonly key: KeyObject, readonly trust: JobTrust) {}
  static fromJwk(input: unknown): JobSigner {
    const parsed = keySchema.safeParse(input);
    if (!parsed.success) throw new Error("Invalid daemon job signing key");
    const { kid, ...jwk } = parsed.data;
    try {
      if ([jwk.x, jwk.d].some(s => Buffer.from(s, "base64url").toString("base64url") !== s)) throw new Error();
      const key = createPrivateKey({ key: jwk, format: "jwk" });
      if (createPublicKey(key).export({format:"jwk"}).x !== jwk.x) throw new Error();
      return new JobSigner(key, {kid, publicKey:jwk.x});
    } catch { throw new Error("Invalid daemon job signing key"); }
  }
  static async fromFile(filename: string): Promise<JobSigner> {
    // Secret mount only: no environment literal, auto-generated key, or symlink.
    try {
      if ((await lstat(filename)).isSymbolicLink()) throw new Error();
      const handle = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const stat = await handle.stat();
        if (!stat.isFile() || stat.size > 4096 || (stat.mode & 0o077) !== 0
          || (stat.uid !== process.getuid?.() && stat.uid !== 0)) throw new Error();
        return JobSigner.fromJwk(JSON.parse(await handle.readFile("utf8")));
      } finally { await handle.close(); }
    } catch { throw new Error("Daemon job signing key is unavailable or unsafe"); }
  }
  sign(job: ManagementJob): string {
    const payload = jobSchema.parse(job);
    const input = `${Buffer.from(canonicalJobJson({alg:"EdDSA",kid:this.trust.kid,typ:JOB_TYPE})).toString("base64url")}.${Buffer.from(canonicalJobJson(payload)).toString("base64url")}`;
    return `${input}.${sign(null, Buffer.from(input), this.key).toString("base64url")}`;
  }
}
