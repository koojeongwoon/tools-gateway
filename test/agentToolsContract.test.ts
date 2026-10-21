import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import { describe, expect, it, vi } from "vitest";
import { validateAgentToolsArguments, validateAgentToolsResult } from "../src/policy/agentToolsContract.js";
import { parseGatewayConfig } from "../src/config/upstreamConfig.js";
import { ToolRegistry } from "../src/upstream/toolRegistry.js";
import { ToolPolicy } from "../src/policy/toolPolicy.js";
import { createGatewayServer } from "../src/server/createGatewayServer.js";

const envelope = (files: Record<string,string> = {}) => ({exit_code:0,stdout:"mail@example.com\n",stderr:"",files});
const reply = (data: ReturnType<typeof envelope>) => ({content:[{type:"text" as const,text:JSON.stringify(data)}],structuredContent:data});

describe("owner-bound agent-tools data contract", () => {
  it("preserves binary files, Korean content and owner-requested output exactly", () => {
    const image=Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),Buffer.from(Array.from({length:256},(_,i)=>i))]).toString("base64");
    expect(()=>validateAgentToolsArguments("wordpress",{argv:["upload-media","input-0.png"],files:{"input-0.png":image},stdin:""})).not.toThrow();
    const result=reply(envelope({"output.png":image}));
    expect(validateAgentToolsResult("thumbnail_tool",result)).toBe(result);
    expect(result.structuredContent.files["output.png"]).toBe(image);
  });
  it("allows explicit consent handoff but blocks secret-like data in normal commands", () => {
    const code="p2Y9aK7qL3vX8nR4mT6cW1fH5sD0jB9uE2gI7oN";
    expect(()=>validateAgentToolsArguments("auth_google_ads",{argv:["complete"],stdin:code,files:{"state.txt":Buffer.from(code).toString("base64")}})).not.toThrow();
    expect(()=>validateAgentToolsArguments("search",{argv:[code]})).toThrow();
    expect(()=>validateAgentToolsArguments("wordpress",{argv:["create-draft"],files:{"input-0.txt":Buffer.from(code).toString("base64")}})).toThrow();
  });
  it("rejects unknown commands, traversal attachments, malformed data and unsolicited outputs", () => {
    for (const [command,args] of [["unknown",{argv:[]}],["wordpress",{argv:[],files:{"../token":"eA=="}}],
      ["wordpress",{argv:[],files:{"input-0.txt":"!bad"}}],["search",{argv:[],stdin:"unexpected"}],
      ["search",{argv:[],Authorization:"Bearer test"}]] as const) {
      expect(()=>validateAgentToolsArguments(command,args)).toThrow();
    }
    expect(()=>validateAgentToolsResult("search",reply(envelope({"state.txt":"eA=="})))).toThrow();
    expect(()=>validateAgentToolsResult("search",reply({...envelope(),exit_code:-9}))).toThrow();
  });
  it("requires an operator-configured cluster IAM-delegated agent-tools upstream", () => {
    const upstream={id:"agent-tools",toolPrefix:"agent_tools",networkScope:"cluster",endpoint:"http://agent-tools.hermes.svc.cluster.local:8080/mcp",transport:"streamable-http",enabled:true,payloadContract:"agent-tools-cli-v1",auth:{mode:"gateway-delegation",audience:"agent-tools",targetTenantId:"tenant"}};
    const config={upstreams:[upstream],toolPolicy:{default:"deny",allow:["agent_tools.*"]}};
    expect(parseGatewayConfig(config).upstreams[0]!.payloadContract).toBe("agent-tools-cli-v1");
    expect(()=>parseGatewayConfig({...config,upstreams:[{...upstream,auth:{mode:"provider-credential"}}]})).toThrow();
    expect(()=>parseGatewayConfig({...config,upstreams:[{...upstream,networkScope:"external",endpoint:"https://example.com/mcp"}]})).toThrow();
  });
  it("routes a real MCP call with data preservation, policy enforcement and body-free audit", async () => {
    const image=Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),Buffer.alloc(100,29)]).toString("base64");
    const callTool=vi.fn(async()=>reply(envelope({"output.png":image})));
    const connection={id:"agent-tools",toolPrefix:"agent_tools",listTools:async()=>[{name:"thumbnail_tool",inputSchema:{type:"object" as const,properties:{argv:{type:"array",items:{type:"string"}},files:{type:"object"},stdin:{type:"string"}},required:["argv"]}}],callTool,close:async()=>undefined};
    const registry=new ToolRegistry([connection]);await registry.refresh();
    const log=vi.fn(async(_entry: unknown)=>undefined);
    const server=createGatewayServer(registry,new ToolPolicy({default:"deny",allow:["agent_tools.thumbnail_tool"],deny:[]}),undefined,{log} as any,{userId:"owner"},undefined,undefined,[{upstreamId:"agent-tools",toolPrefix:"agent_tools"}]);
    const client=new Client({name:"relay-test",version:"1"});const [a,b]=InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(b),client.connect(a)]);
    try {
      const result=await client.callTool({name:"agent_tools.thumbnail_tool",arguments:{argv:["--title","한글 제목","--out","output.png"],files:{},stdin:""}});
      expect(result).toMatchObject(reply(envelope({"output.png":image})));
      expect(callTool).toHaveBeenCalledOnce();
      expect(log.mock.calls[0]?.[0]).toMatchObject({arguments:{argvCount:4,attachmentCount:0,stdinPresent:false}});
      expect(JSON.stringify(log.mock.calls)).not.toContain("한글 제목");
    } finally {await client.close();await server.close();}
  });
});
