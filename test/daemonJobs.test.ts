import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { VerifiedJob, type JobBinding, type JobTrust, type PriorJob, type ResourceState } from "../src/daemonManagement/jobs/contract.js";
interface Vector {
  id: string; description: string; compact: string; trust: JobTrust; binding: JobBinding;
  now: number; admission_now: number; current: ResourceState; prior: PriorJob | null; expected: string;
}
const fixture = JSON.parse(readFileSync(new URL("./fixtures/daemon-jobs-v1/vectors.json", import.meta.url), "utf8")) as { cases: Vector[] };
it.each(fixture.cases)("$id: $description", async vector => {
  let actual: string;
  const initial = JSON.stringify(vector.current);
  try {
    const verified = await VerifiedJob.verify(vector.compact, vector.trust, vector.binding, vector.now);
    const plan = verified.plan(vector.current, vector.admission_now, vector.prior ?? undefined);
    actual = plan.decision;
    if (plan.decision === "prepare_revoke") {
      expect(plan.next_state_version).toBe(vector.current.state_version+1);
      expect(plan.expected_state_version).toBe(vector.current.state_version);
      expect(plan.resource_id).toBe(vector.current.resource.id);
      expect(plan.digest).toMatch(/^[a-f0-9]{64}$/);
    }
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error)) throw error;
    actual = String(error.code);
  }
  expect(actual).toBe(vector.expected);
  // An accepted plan is not a mutation or an execution-completion receipt.
  expect(JSON.stringify(vector.current)).toBe(initial);
});
