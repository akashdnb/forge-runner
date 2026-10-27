const crypto = require('node:crypto');

const VERSION = 'forge-public-runner-v2';
const OPERATIONS = Object.freeze(new Set(['sha256', 'ffprobe', 'ffmpeg', 'whisper', 'package']));
const WORKERS = Object.freeze(new Set(['transcription', 'media-ffmpeg', 'captions', 'qa', 'package']));
const LIMITS = Object.freeze({
  maxManifestBytes: 256 * 1024,
  maxInputs: 8,
  maxInputBytes: 512 * 1024 * 1024,
  maxTotalInputBytes: 2 * 1024 * 1024 * 1024,
  maxOutputBytes: 512 * 1024 * 1024,
  maxOutputArtifacts: 4,
  maxArgs: 32,
  maxArgBytes: 512,
  maxRuntimeMs: 25 * 60 * 1000,
  maxCallbackBytes: 64 * 1024
});

function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
function timingSafeHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || !/^[a-f0-9]+$/.test(a) || !/^[a-f0-9]+$/.test(b)) return false;
  const x = Buffer.from(a, 'hex'); const y = Buffer.from(b, 'hex');
  return x.length > 0 && x.length === y.length && crypto.timingSafeEqual(x, y);
}
function fail(code, message) { throw Object.assign(new Error(message), { code }); }
function stripDerived(manifest) { const value = structuredClone(manifest); delete value.payloadHash; delete value.signature; delete value._callbackToken; return value; }

function validateManifest(manifest, { attemptId, now = Date.now, artifactHosts = [], uploadHosts = [] } = {}) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) fail('MANIFEST_MALFORMED', 'manifest must be an object');
  if (manifest.version !== VERSION) fail('MANIFEST_VERSION', 'unsupported manifest version');
  if (manifest.attemptId !== attemptId) fail('ATTEMPT_MISMATCH', 'attempt identity mismatch');
  if (!WORKERS.has(manifest.workerType)) fail('WORKER_NOT_ALLOWED', 'worker type is not allowlisted');
  if (!OPERATIONS.has(manifest.input?.operation)) fail('OPERATION_NOT_ALLOWED', 'operation is not allowlisted');
  const expiry = Date.parse(manifest.expiresAt || '');
  if (!Number.isFinite(expiry) || expiry <= now()) fail('MANIFEST_EXPIRED', 'manifest expired or invalid');
  if (expiry - now() > 15 * 60 * 1000) fail('MANIFEST_TTL', 'manifest lifetime exceeds policy');
  if (manifest.policy?.allowPrivateCheckout || manifest.policy?.allowForgeSourceCheckout || manifest.policy?.allowSecretForwarding || manifest.policy?.allowArbitraryRepository || manifest.policy?.allowArbitraryRef) fail('POLICY_VIOLATION', 'unsafe execution policy requested');
  if (!manifest.input || !Array.isArray(manifest.input.artifactUrls) || !Array.isArray(manifest.input.artifactHashes)) fail('INPUT_CONTRACT', 'artifact URLs and hashes are required');
  if (manifest.input.artifactUrls.length !== manifest.input.artifactHashes.length || manifest.input.artifactUrls.length > LIMITS.maxInputs) fail('INPUT_LIMIT', 'invalid input count');
  if (manifest.input.artifactUrls.some(u => typeof u !== 'string' || u.length > 2048)) fail('INPUT_URL', 'invalid artifact URL');
  for (const raw of manifest.input.artifactUrls) {
    let u; try { u = new URL(raw); } catch { fail('INPUT_URL', 'invalid artifact URL'); }
    if (u.protocol !== 'https:') fail('NETWORK_POLICY', 'artifact URLs must use HTTPS');
    if (artifactHosts.length && !artifactHosts.includes(u.hostname)) fail('NETWORK_POLICY', `artifact host ${u.hostname} is not allowlisted`);
    if (u.username || u.password || u.port && u.port !== '443') fail('NETWORK_POLICY', 'artifact URL contains forbidden authority components');
  }
  for (const hash of manifest.input.artifactHashes) if (typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)) fail('INPUT_HASH', 'invalid SHA-256 input hash');
  if (!manifest.output || manifest.output.maxArtifacts > LIMITS.maxOutputArtifacts) fail('OUTPUT_LIMIT', 'output artifact limit exceeded');
  if (manifest.output.uploadUrl) {
    let u; try { u = new URL(manifest.output.uploadUrl); } catch { fail('OUTPUT_URL', 'invalid upload URL'); }
    if (u.protocol !== 'https:' || (uploadHosts.length && !uploadHosts.includes(u.hostname)) || u.username || u.password) fail('NETWORK_POLICY', 'upload URL is outside the egress policy');
  }
  const parameters = manifest.input.parameters;
  if (!parameters || typeof parameters !== 'object' || Array.isArray(parameters)) fail('PARAMETERS', 'parameters must be an object');
  if (Object.keys(parameters).length > 16) fail('PARAMETERS', 'too many parameters');
  if (manifest.input.operation === 'ffmpeg') validateArgs(parameters.args);
  if (manifest.input.operation === 'whisper' && parameters.args !== undefined) validateArgs(parameters.args);
  const derived = sha256(canonicalJson(stripDerived(manifest)));
  if (!timingSafeHex(derived, manifest.payloadHash)) fail('MANIFEST_INTEGRITY', 'manifest checksum mismatch');
  return true;
}
function validateArgs(args) {
  if (!Array.isArray(args) || args.length === 0 || args.length > LIMITS.maxArgs) fail('ARGS_POLICY', 'invalid process arguments');
  for (const arg of args) {
    if (typeof arg !== 'string' || Buffer.byteLength(arg) > LIMITS.maxArgBytes || /[\0\r\n]/.test(arg)) fail('ARGS_POLICY', 'unsafe process argument');
    if (/^(--(exec|eval|filter_complex_script|load_plugin|enable-lib|protocol_whitelist)|-fscript)$/i.test(arg)) fail('ARGS_POLICY', 'unsafe ffmpeg argument');
    if (/^(https?|file|ftp|rtmp|tcp|udp):/i.test(arg)) fail('NETWORK_POLICY', 'network-capable process argument is forbidden');
    if (arg.includes('..' + require('node:path').sep) || arg.includes('../') || arg.includes('..\\')) fail('PATH_TRAVERSAL', 'path traversal is forbidden');
  }
}

module.exports = { VERSION, OPERATIONS, WORKERS, LIMITS, sha256, canonicalJson, validateManifest, validateArgs, timingSafeHex };
