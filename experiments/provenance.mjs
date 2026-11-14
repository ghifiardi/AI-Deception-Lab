/**
 * Experiment provenance and signed audit checkpoints.
 *
 * Signing: Ed25519 via node:crypto. The private key lives OUTSIDE the
 * repository by default (~/.config/gatra-deception-lab/signing-ed25519.pem,
 * mode 0600) and is never written into results; results embed the public
 * key and its fingerprint. A self-generated key proves the record has not
 * changed since it was signed and that the signer held this key. It does not
 * prove the signer's identity: pin the fingerprint out of band (see DESIGN §3).
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { cpus, homedir, platform, release, arch, totalmem } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical } from '../lab/services/harness.mjs';

export const sha256 = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
export const DEFAULT_KEY_PATH = join(homedir(), '.config', 'gatra-deception-lab', 'signing-ed25519.pem');

export function environment(extra = {}) {
  const git = (args, cwd) => {
    try {
      return execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      return null;
    }
  };
  // fileURLToPath (not URL.pathname): paths with spaces or '&' must not stay percent-encoded.
  const here = dirname(fileURLToPath(import.meta.url));
  const commit = git(['rev-parse', 'HEAD'], here);
  const dirty = git(['status', '--porcelain', '--', '..'], here);
  return {
    git: { commit, short: commit?.slice(0, 7) ?? null, dirty: Boolean(dirty), branch: git(['rev-parse', '--abbrev-ref', 'HEAD'], here) },
    node: process.version,
    platform: `${platform()} ${release()} ${arch()}`,
    cpu: cpus()[0]?.model ?? null,
    cpuCount: cpus().length,
    memoryBytes: totalmem(),
    ...extra,
  };
}

/** Load or create the lab signing key. Never returns the private key material in a serialisable form. */
export function loadSigningKey(path = process.env.LAB_SIGNING_KEY ?? DEFAULT_KEY_PATH) {
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const { privateKey } = generateKeyPairSync('ed25519');
    writeFileSync(path, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    chmodSync(path, 0o600);
  }
  const privateKey = createPrivateKey(readFileSync(path));
  const publicKeyPem = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  const der = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  return { privateKey, publicKeyPem, publicKeyFingerprint: `SHA256:${createHash('sha256').update(der).digest('base64')}`, keyPath: path };
}

/** Sign a canonical-JSON payload. Returns { payload, signature } where signature is base64. */
export function signPayload(key, payload) {
  return { payload, signature: sign(null, Buffer.from(canonical(payload), 'utf8'), key.privateKey).toString('base64') };
}

export function verifyPayload(publicKeyPem, signed) {
  try {
    return verify(null, Buffer.from(canonical(signed.payload), 'utf8'), createPublicKey(publicKeyPem), Buffer.from(signed.signature, 'base64'));
  } catch {
    return false;
  }
}

/** Hash of the whole result except its `signing` block. */
export function resultDigest(result) {
  const { signing: _s, ...rest } = result;
  return sha256(canonical(rest));
}

/** Verify every checkpoint and the final signature of a result. */
export function verifySignatures(result, { pinnedFingerprint } = {}) {
  const s = result.signing;
  if (!s) return { ok: false, reason: 'unsigned result' };
  const fp = (() => {
    try {
      return `SHA256:${createHash('sha256').update(createPublicKey(s.publicKeyPem).export({ type: 'spki', format: 'der' })).digest('base64')}`;
    } catch {
      return null;
    }
  })();
  if (fp !== s.publicKeyFingerprint) return { ok: false, reason: 'public key does not match its fingerprint' };
  if (pinnedFingerprint && pinnedFingerprint !== fp) return { ok: false, reason: `key ${fp} is not the pinned key` };
  for (const [i, cp] of (s.checkpoints ?? []).entries()) {
    if (!verifyPayload(s.publicKeyPem, cp)) return { ok: false, reason: `checkpoint ${i + 1} signature invalid` };
    const run = result.runs?.[cp.payload.runIndex];
    if (!run || run.logHead !== cp.payload.logHead) return { ok: false, reason: `checkpoint ${i + 1} does not match run log head` };
  }
  if (!verifyPayload(s.publicKeyPem, s.final)) return { ok: false, reason: 'final signature invalid' };
  if (s.final.payload.resultSha256 !== resultDigest(result)) return { ok: false, reason: 'result content changed after signing' };
  return { ok: true, fingerprint: fp, checkpoints: s.checkpoints?.length ?? 0 };
}
