const test = require('node:test');
const assert = require('node:assert/strict');
const { VERSION, canonicalJson, sha256, validateManifest } = require('../policy');

function manifest(overrides = {}) {
  const base = {
    version: VERSION, executionId: 'e1', attemptId: 'a1', jobId: 'j1', projectId: 'p1', tenantKey: 't1', workerType: 'media-ffmpeg', capacityClass: 'cpu-large', idempotencyKey: 'i1', expiresAt: new Date(Date.now() + 60_000).toISOString(),
    input: { artifactUrls: ['https://artifacts.example.test/in/a'], artifactHashes: ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], operation: 'sha256', parameters: {} },
    output: { prefix: 'public-runner/e1/', uploadUrl: 'https://artifacts.example.test/out/e', maxArtifacts: 1 },
    policy: { allowPrivateCheckout: false, allowForgeSourceCheckout: false, allowSecretForwarding: false, allowArbitraryRepository: false, allowArbitraryRef: false }
  };
  const value = { ...base, ...overrides }; value.payloadHash = sha256(canonicalJson(value)); return value;
}

test('accepts valid manifest and bounded hosts', () => assert.equal(validateManifest(manifest(), { attemptId: 'a1', artifactHosts: ['artifacts.example.test'], uploadHosts: ['artifacts.example.test'] }), true));
test('rejects tampered payload hash', () => { const m = manifest(); m.input.operation = 'ffmpeg'; assert.throws(() => validateManifest(m, { attemptId: 'a1' }), /checksum/); });
test('rejects stale attempt', () => assert.throws(() => validateManifest(manifest(), { attemptId: 'a2' }), /attempt identity/i));
test('rejects expired manifest', () => assert.throws(() => validateManifest(manifest({ expiresAt: new Date(Date.now() - 1).toISOString() }), { attemptId: 'a1' }), /expired/i));
test('rejects private checkout and secret forwarding', () => assert.throws(() => validateManifest(manifest({ policy: { allowPrivateCheckout: true } }), { attemptId: 'a1' }), /unsafe execution/i));
test('rejects unapproved network host', () => assert.throws(() => validateManifest(manifest(), { attemptId: 'a1', artifactHosts: ['safe.example.test'] }), /not allowlisted/i));
test('rejects non-https and embedded credentials', () => { const m = manifest({ input: { ...manifest().input, artifactUrls: ['http://user:pass@artifacts.example.test/a'] } }); assert.throws(() => validateManifest(m, { attemptId: 'a1' }), /HTTPS|authority/i); });
test('rejects arbitrary repository/ref policy', () => assert.throws(() => validateManifest(manifest({ policy: { allowArbitraryRepository: true } }), { attemptId: 'a1' }), /unsafe execution/i));
test('rejects dependency/network-capable ffmpeg arguments', () => { const m = manifest({ input: { ...manifest().input, operation: 'ffmpeg', parameters: { args: ['-i', 'https://evil.example/x', 'out.mp4'] } } }); m.payloadHash = sha256(canonicalJson({ ...m, payloadHash: undefined })); delete m.payloadHash; m.payloadHash = sha256(canonicalJson(m)); assert.throws(() => validateManifest(m, { attemptId: 'a1' }), /network-capable/i); });
