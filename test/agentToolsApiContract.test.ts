import { describe, expect, it } from 'vitest';
import { validateAgentToolsArguments, validateAgentToolsResult } from '../src/policy/agentToolsContract.js';
const invoke = (operation: string, args: Record<string, unknown>) => validateAgentToolsArguments('api', {operation, arguments: args});
const result = (data: unknown) => validateAgentToolsResult('api', {content: [{type: 'text', text: JSON.stringify(data)}], structuredContent: data as Record<string, unknown>});
describe('agent-tools Python/native contract', () => {
  it('accepts only generic profiles and bounded transfer metadata', () => {
    expect(() => invoke('broker.forward', {operation:'workspace', method:'PATCH', url:'https://www.googleapis.com/drive/v3/files/fixture', content_ref:'a'.repeat(32)})).not.toThrow();
    expect(() => invoke('blob.begin', {size:60*1024*1024, sha256:'b'.repeat(64)})).not.toThrow();
    expect(() => invoke('broker.json', {operation:'codex.models'})).toThrow();
    expect(() => invoke('python.eval', {code:'print(1)'})).toThrow();
    expect(() => invoke('blob.read', {reference:'../../etc/passwd', offset:0, length:5})).toThrow();
    expect(() => invoke('blob.read', {reference:'a'.repeat(32), offset:0, length:1024*1024+1})).toThrow();
  });
  it('rejects credential headers, ambiguous bodies, server paths and malformed encoding', () => {
    const forward={operation:'workspace',method:'GET',url:'https://www.googleapis.com/drive/v3/files',content:''};
    for (const change of [{headers:{Authorization:'secret'}},{headers:{Accept:'a',accept:'b'}},
      {content_ref:'a'.repeat(32)},{content:'!'}, {url:'https://user:password@www.googleapis.com/drive/v3/files'},
      {url:'http://www.googleapis.com/drive/v3/files'}]) {
      expect(() => invoke('broker.forward', {...forward,...change})).toThrow();
    }
    expect(() => invoke('cover.generate', {title:'x',subtitle:'',category:'',output_path:'/etc/token'})).toThrow();
  });
  it('preserves arbitrary bytes, PII and 64-bit resource IDs without Node number conversion', () => {
    const encoded=Buffer.from('{"id":9223372036854775807,"email":"reader@example.com"}').toString('base64');
    const data={ok:true,kind:'json',content:encoded};
    expect(result(data).structuredContent).toEqual(data);
    expect(() => result({ok:true,kind:'bytes',content_ref:'c'.repeat(32),content_size:64*1024*1024,sha256:'d'.repeat(64)})).not.toThrow();
    expect(() => result({ok:true,kind:'bytes',content_ref:'c'.repeat(32),content_size:64*1024*1024+1,sha256:'d'.repeat(64)})).toThrow();
    expect(() => result({ok:true,kind:'response',content:'',status_code:200,headers:{'set-cookie':'secret'}})).toThrow();
  });
});
