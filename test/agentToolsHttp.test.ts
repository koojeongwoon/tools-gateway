import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";
import { RemoteMcpConnection } from "../src/upstream/remoteMcpConnection.js";
import { ToolRegistry } from "../src/upstream/toolRegistry.js";
import { createGatewayServer } from "../src/server/createGatewayServer.js";
import { ToolPolicy } from "../src/policy/toolPolicy.js";

const python=process.env.AGENT_TOOLS_TEST_PYTHON;
describe.skipIf(!python)("agent-tools real HTTP integration", () => {
  it("routes Gateway MCP → HTTP upstream → isolated extracted CLI with no Hermes checkout", async () => {
    const peer=spawn(python!,["-u","test/fixtures/agent_tools_peer.py"],{stdio:["ignore","pipe","pipe"]});
    let connection: RemoteMcpConnection | undefined;
    let server: ReturnType<typeof createGatewayServer> | undefined;
    let client: Client | undefined;
    try {
      const port=await new Promise<number>((resolve,reject)=>{
        let data="";
        const deadline=setTimeout(()=>reject(new Error("agent-tools peer startup timed out")),15000);
        peer.stdout.on("data",chunk=>{data+=String(chunk);const match=/LISTEN:(\d+)/.exec(data);if(match){clearTimeout(deadline);resolve(Number(match[1]));}});
        peer.once("exit",()=>{clearTimeout(deadline);reject(new Error("agent-tools peer exited"));});
      });
      // The listener is open before uvicorn starts accepting requests.
      connection=await RemoteMcpConnection.connect({id:"agent-tools",toolPrefix:"agent_tools",networkScope:"cluster",endpoint:`http://127.0.0.1:${port}/mcp`,transport:"streamable-http",enabled:true,timeoutMs:20000,auth:{mode:"gateway-delegation",audience:"agent-tools",targetTenantId:"fixture"},headers:{},payloadContract:"agent-tools-cli-v1"},{Authorization:"Bearer synthetic-gateway-delegation"});
      const registry=new ToolRegistry([connection]);await registry.refresh();
      server=createGatewayServer(registry,new ToolPolicy({default:"deny",allow:["agent_tools.*"],deny:[]}),undefined,undefined,undefined,undefined,undefined,[{upstreamId:"agent-tools",toolPrefix:"agent_tools"}]);
      client=new Client({name:"integration-consumer",version:"1"});const [a,b]=InMemoryTransport.createLinkedPair();
      await Promise.all([server.connect(b),client.connect(a)]);
      expect((await client.listTools()).tools).toHaveLength(9);
      const help=await client.callTool({name:"agent_tools.wordpress",arguments:{argv:["--help"],files:{},stdin:""}});
      expect(help.isError).not.toBe(true);
      const content=help.content[0]!;
      if(content.type!=="text")throw new Error("Expected text envelope");
      const payload=JSON.parse(content.text);
      expect(payload.exit_code).toBe(0);expect(payload.stdout).toContain("create-draft");
      // A malformed remote file path is rejected before reading any server file.
      const rejected=await client.callTool({name:"agent_tools.wordpress",arguments:{argv:["upload-media","/etc/passwd"],files:{},stdin:""}});
      expect(rejected.isError).toBe(true);
      const api = async (operation: string, args: Record<string, unknown>) => {
        const result=await client!.callTool({name:"agent_tools.api",arguments:{operation,arguments:args}});
        expect(result.isError).not.toBe(true);
        const block=result.content[0]!;
        if(block.type!=="text")throw new Error("Expected API envelope");
        return JSON.parse(block.text);
      };
      const json = (data: any) => JSON.parse(Buffer.from(data.content,"base64").toString());
      // Real Gateway -> HTTP -> API -> Broker boundary with a synthetic provider only.
      // Chunk transfer crosses the old CLI 8 MiB limit without expanding the HTTP parser limit.
      const bytes=Buffer.alloc(9*1024*1024+7,0x61), hash=createHash("sha256").update(bytes).digest("hex");
      const ref=json(await api("blob.begin",{size:bytes.length,sha256:hash}));
      for(let offset=0;offset<bytes.length;offset+=1024*1024){
        const chunk=bytes.subarray(offset,offset+1024*1024);
        expect(json(await api("blob.append",{reference:ref,offset,content:chunk.toString("base64")}))).toBe(offset+chunk.length);
      }
      await api("blob.seal",{reference:ref});
      const forward={operation:"workspace",method:"PATCH",url:"https://www.googleapis.com/upload/drive/v3/files/fixture?uploadType=media",content_ref:ref};
      const echoed=await api("broker.forward",forward);
      expect(echoed.ok).toBe(true);expect(echoed.content_size).toBe(bytes.length);expect(echoed.sha256).toBe(hash);
      const chunks: Buffer[]=[];
      for(let offset=0;offset<bytes.length;offset+=1024*1024){
        const chunk=await api("blob.read",{reference:echoed.content_ref,offset,length:1024*1024});
        chunks.push(Buffer.from(chunk.content,"base64"));
      }
      expect(Buffer.concat(chunks).equals(bytes)).toBe(true);
      await api("blob.release",{reference:echoed.content_ref});
      expect((await api("broker.forward",forward)).ok).toBe(false);

    } finally {
      await client?.close();await server?.close();await connection?.close();
      peer.kill("SIGTERM");await once(peer,"exit").catch(()=>undefined);
    }
  },60000);
});
