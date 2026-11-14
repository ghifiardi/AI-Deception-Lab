import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { sha256Hex } from '../src/engine/sha256.ts';
import { GENESIS_HASH, canonicalJson, verifyChain } from '../src/engine/hash.ts';
import { compileRun } from '../src/engine/simulator.ts';

const nodeSha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

test('SHA-256 matches FIPS 180-4 vectors', () => {
  assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(
    sha256Hex('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  );
});

test('SHA-256 matches node:crypto on padding boundaries and multi-byte UTF-8', () => {
  for (let len = 0; len < 200; len++) {
    const s = 'x'.repeat(len);
    assert.equal(sha256Hex(s), nodeSha(s), `length ${len}`);
  }
  for (const s of ['é', '漢字', '→ arrow', '🙂 emoji', 'Ünïcødé\u0000nul', 'a'.repeat(1000) + '€']) {
    assert.equal(sha256Hex(s), nodeSha(s), JSON.stringify(s));
  }
  let seed = 7;
  for (let i = 0; i < 300; i++) {
    let s = '';
    const n = (seed = (seed * 1103515245 + 12345) >>> 0) % 300;
    for (let j = 0; j < n; j++) s += String.fromCharCode(((seed = (seed * 1103515245 + 12345) >>> 0) % 0x3000) + 32);
    assert.equal(sha256Hex(s), nodeSha(s));
  }
});

test('every event hash is the SHA-256 of its canonical body (independent check with node:crypto)', () => {
  const { events } = compileRun({ scenario: 'egress-block', mode: 'adaptive', seed: 9 });
  let prev = GENESIS_HASH;
  for (const e of events) {
    const { hash, ...body } = e;
    assert.equal(e.prevHash, prev);
    assert.equal(hash, nodeSha(canonicalJson(body)));
    assert.match(hash, /^[0-9a-f]{64}$/);
    prev = hash;
  }
});

test('verifyChain reports the reason and position of a break', () => {
  const { events } = compileRun({ scenario: 'api-canary', mode: 'static', seed: 9 });
  const forged = events.map((e) => ({ ...e }));
  forged[4] = { ...forged[4]!, summary: 'edited' };
  assert.deepEqual(verifyChain(forged), { ok: false, brokenAt: 5, reason: 'hash does not match record content' });
  // An attacker who recomputes the edited record's hash still breaks the next link.
  const { hash: _h, ...body } = forged[4]!;
  forged[4] = { ...forged[4]!, hash: nodeSha(canonicalJson(body)) };
  assert.deepEqual(verifyChain(forged), { ok: false, brokenAt: 6, reason: 'prevHash does not match previous record' });
});

test('canonical JSON is key-order independent and drops undefined', () => {
  assert.equal(canonicalJson({ b: 1, a: [2, { d: undefined, c: 'x' }] }), '{"a":[2,{"c":"x"}],"b":1}');
  assert.equal(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }));
});
