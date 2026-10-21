/** Typed data transport for the operator-bound agent-tools upstream only. */
import { OutboundSecretLeakGuard } from "./outboundSecretLeakGuard.js";
const secretGuard = new OutboundSecretLeakGuard();
const MiB = 1024 * 1024;
const operations = new Set(['broker.json', 'broker.forward', 'documents.read', 'documents.fetch',
  'documents.extract', 'documents.validate', 'cover.generate', 'blob.begin', 'blob.append',
  'blob.seal', 'blob.read', 'blob.release']);
const jsonOperations = new Set(['search', 'google.authorization.start', 'google.authorization.complete',
  'google.ads.authorization.start', 'google.ads.authorization.complete']);
const profiles = new Set(['workspace', 'wordpress', 'naver.keywords', 'google.keywords']);
function reject(): never { throw new Error('Invalid agent-tools API contract'); }
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) reject();
  return value as Record<string, unknown>;
}
function fields(value: Record<string, unknown>, allowed: string[], required: string[] = []): void {
  if (Object.keys(value).some(key => !allowed.includes(key)) || required.some(key => !(key in value))) reject();
}
function integer(value: unknown, max: number, min = 0): void {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) reject();
}
function ref(value: unknown): void { if (typeof value !== 'string' || !/^[a-f0-9]{32}$/.test(value)) reject(); }
function sha(value: unknown): void { if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) reject(); }
function content(value: unknown, max = 8 * MiB): Buffer {
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4) reject();
  const raw = Buffer.from(value as string, 'base64');
  if (raw.length > max || raw.toString('base64') !== value) reject();
  return raw;
}
export function validateAgentToolsApiArguments(envelope: Record<string, unknown>): void {
  fields(envelope, ['operation', 'arguments'], ['operation', 'arguments']);
  const op = envelope.operation;
  if (typeof op !== 'string' || !operations.has(op)) reject();
  const args = object(envelope.arguments);
  if (Buffer.byteLength(JSON.stringify(args)) > 12 * MiB) reject();
  if (op.startsWith('blob.')) {
    const keys: Record<string, string[]> = {
      'blob.begin': ['size', 'sha256'], 'blob.append': ['reference', 'offset', 'content'],
      'blob.seal': ['reference'], 'blob.read': ['reference', 'offset', 'length'], 'blob.release': ['reference'],
    };
    fields(args, keys[op]!, keys[op]!);
    if (op === 'blob.begin') { integer(args.size, 512 * MiB); sha(args.sha256); }
    else {
      ref(args.reference);
      if ('offset' in args) integer(args.offset, 512 * MiB);
      if (op === 'blob.append' && content(args.content, MiB).length === 0) reject();
      if (op === 'blob.read') integer(args.length, MiB, 1);
    }
  } else if (op === 'broker.json') {
    fields(args, ['operation', 'payload'], ['operation']);
    if (!jsonOperations.has(args.operation as string)) reject();
    if (args.operation === 'search') {
      const payload = object(args.payload);
      fields(payload, ['query', 'max_results'], ['query']);
      if (typeof payload.query !== 'string' || !payload.query.trim()) reject();
      if (payload.max_results !== undefined) integer(payload.max_results, Number.MAX_SAFE_INTEGER, 1);
      secretGuard.validate({query: payload.query});
    } else if ((args.operation as string).endsWith('.start')) {
      if (args.payload != null) fields(object(args.payload), []);
    } else {
      const payload = object(args.payload);
      fields(payload, ['code_or_url', 'state'], ['code_or_url', 'state']);
      if (typeof payload.code_or_url !== 'string' || !payload.code_or_url.trim() || payload.code_or_url.trim().length > 8192
        || typeof payload.state !== 'string' || payload.state.length < 32 || payload.state.length > 4096) reject();
    }
  } else if (op === 'broker.forward') {
    fields(args, ['operation', 'method', 'url', 'content', 'content_ref', 'headers', 'timeout'], ['operation', 'method', 'url']);
    if (!profiles.has(args.operation as string)
      || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(args.method as string)
      || typeof args.url !== 'string' || args.url.length > 16384) reject();
    let target: URL;
    try { target = new URL(args.url as string); } catch { reject(); }
    if (target.protocol !== 'https:' || target.username || target.password || target.hash || target.port) reject();
    if (('content' in args) === ('content_ref' in args)) reject();
    if ('content' in args) content(args.content); else ref(args.content_ref);
    const headers = object(args.headers ?? {});
    if (Object.keys(headers).length > 4) reject();
    const names = new Set<string>();
    for (const [key, value] of Object.entries(headers)) {
      const name = key.toLowerCase();
      if (!['content-type', 'content-disposition', 'accept', 'accept-encoding'].includes(name) || names.has(name)
        || typeof value !== 'string' || value.length > 4096 || /[^\x20-\x7e]/.test(value)) reject();
      names.add(name);
    }
    if (args.timeout !== undefined && (typeof args.timeout !== 'number' || !Number.isFinite(args.timeout)
      || args.timeout <= 0 || args.timeout > 120)) reject();
  } else if (op === 'cover.generate') {
    fields(args, ['title', 'subtitle', 'category', 'meta', 'style', 'accent', 'size_mode'], ['title', 'subtitle', 'category']);
    if (Object.values(args).some(value => typeof value !== 'string' || value.length > 65536)) reject();
    secretGuard.validate(args);
  } else {
    const keys: Record<string, [string[], string[]]> = {
      'documents.read': [['urls', 'limit', 'preserve_html', 'compact_text'], ['urls']],
      'documents.fetch': [['url', 'preserve_html'], ['url']],
      'documents.extract': [['urls', 'format', 'char_limit'], ['urls']],
      'documents.validate': [['url'], ['url']],
    };
    fields(args, ...keys[op]!);
  }
}
export function validateAgentToolsApiResult(value: Record<string, unknown>): void {
  if (typeof value.ok !== 'boolean') reject();
  if (!value.ok) {
    fields(value, ['ok', 'error'], ['ok', 'error']);
    const error = object(value.error);
    fields(error, ['kind', 'message', 'status_code', 'retry_after', 'error_code'], ['kind']);
    if (!['broker_http', 'broker_transport', 'broker', 'document', 'value', 'tool'].includes(error.kind as string)) reject();
    if (error.message !== undefined && (typeof error.message !== 'string' || error.message.length > 512)) reject();
    if (error.kind === 'broker_http') integer(error.status_code, 599, 100);
    if (error.retry_after != null) integer(error.retry_after, 86400, 1);
    if (error.kind === 'broker_transport' && !['connect_timeout', 'read_timeout', 'write_timeout', 'pool_timeout',
      'connect_failed', 'read_failed', 'write_failed', 'protocol_error', 'response_decode_failed',
      'transport_or_response_failed'].includes(error.error_code as string)) reject();
    return;
  }
  fields(value, ['ok', 'kind', 'content', 'content_ref', 'content_size', 'sha256', 'status_code', 'headers'], ['ok', 'kind']);
  if (!['json', 'bytes', 'response'].includes(value.kind as string) || ('content' in value) === ('content_ref' in value)) reject();
  if ('content' in value) {
    const raw = content(value.content);
    if ('content_size' in value || 'sha256' in value) reject();
    // JSON bytes remain encoded to preserve 64-bit IDs through the Node transport.
    if (value.kind === 'json') { try { JSON.parse(raw.toString('utf8')); } catch { reject(); } }
  } else { ref(value.content_ref); integer(value.content_size, 64 * MiB); sha(value.sha256); }
  if (value.kind === 'response') {
    integer(value.status_code, 599, 100);
    const headers = object(value.headers);
    fields(headers, ['content-type', 'x-broker-response-source', 'retry-after']);
    if (Object.values(headers).some(v => typeof v !== 'string' || v.length > 4096)) reject();
  } else if ('headers' in value || 'status_code' in value) reject();
}
