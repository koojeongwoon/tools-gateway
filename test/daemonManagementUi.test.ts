import { runInNewContext } from "node:vm";
import { expect, it, vi } from "vitest";
import { DASHBOARD_HTML } from "../src/ui/dashboardHtml.js";
class Element {
  hidden = false; style: Record<string,string> = {}; className = ""; children: Element[] = []; private text = "";
  set textContent(value: string) { this.text = value; this.children = []; }
  get textContent(): string { return this.text + this.children.map(c => c.textContent).join(" "); }
  set innerHTML(_value: string) { throw new Error("untrusted HTML insertion"); }
  append(...children: Element[]) { this.children.push(...children); }
  replaceChildren() { this.children = []; this.text = ""; }
}
it("renders authorization and stale separately, uses text nodes and clears stale success on network failure", async () => {
  const elements = { "devices-panel": new Element(), "devices-list": new Element() };
  const device = { device_id: '<img src=x onerror=alert(1)>', organization_id: "org", authorization: "denied", freshness: "stale", report: { sequence: 1, observed_at: "2026-09-25T00:00:00Z", status: { connection: "connected", policy: { state: "expired", revision: 2 }, execution: { state: "blocked" }, recent_events: [{ sequence: 1, kind: "denied", timestamp: 0 }] } }, receipt: { received_at: "2026-09-25T00:00:00Z" } };
  const fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({devices:[device]}) }));
  const context = { document: { getElementById: (id: keyof typeof elements) => elements[id], createElement: () => new Element() }, fetch, setTimeout: vi.fn(), AbortSignal, Date };
  const source = DASHBOARD_HTML.slice(DASHBOARD_HTML.indexOf("    async function loadDevices()"), DASHBOARD_HTML.indexOf("    function renderAuthUser"));
  const load = runInNewContext(source + "; loadDevices", context) as () => Promise<void>;
  await load();
  expect(elements["devices-list"].textContent).toContain("IAM 허용 안 됨 · 보고 지연");
  expect(elements["devices-list"].textContent).toContain(device.device_id);
  expect(elements["devices-list"].textContent).toContain("정책 만료 (v2) · 실행 차단");
  fetch.mockRejectedValue(new Error("offline")); await load();
  expect(elements["devices-list"].textContent).toContain("상태를 확인할 수 없습니다");
  expect(elements["devices-list"].children).toHaveLength(0);
});
it("shows matched job outcomes as observations and removes success on result fetch failure", async () => {
  const elements={"jobs-panel":new Element(),"jobs-list":new Element()};
  const jobs=[{job_id:"job-1",device_id:"device",resource:{id:"<script>bad</script>"},state:"completed",freshness:"stale",observed_at:"2026-09-25T00:00:00Z"},
    {job_id:"job-2",device_id:"device",resource:{id:"worker"},state:"termination_unknown",freshness:"fresh",observed_at:null},
    {job_id:"job-3",device_id:"device",resource:{id:"worker"},state:"expired_unconfirmed",freshness:"stale",observed_at:null}];
  const fetch=vi.fn(async()=>({ok:true,status:200,json:async()=>({jobs})}));
  const source=DASHBOARD_HTML.slice(DASHBOARD_HTML.indexOf("    async function loadJobs()"),DASHBOARD_HTML.indexOf("    function renderAuthUser"));
  const load=runInNewContext(source+";loadJobs",{document:{getElementById:(id:keyof typeof elements)=>elements[id],createElement:()=>new Element()},fetch,setTimeout:vi.fn(),AbortSignal,Date}) as ()=>Promise<void>;
  await load();expect(elements["jobs-list"].textContent).toContain("회수 완료 관측");
  expect(elements["jobs-list"].textContent).toContain("보고 지연 · 현재 상태 미확인");
  expect(elements["jobs-list"].textContent).toContain("종료 미확인");expect(elements["jobs-list"].textContent).toContain("집행 여부 미확인");
  fetch.mockRejectedValue(new Error("offline"));await load();expect(elements["jobs-list"].children).toHaveLength(0);
  expect(elements["jobs-list"].textContent).not.toContain("회수 완료");
});
