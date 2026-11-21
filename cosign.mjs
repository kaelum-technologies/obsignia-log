// OBSIGNIA co-signer. For an independent party (an auditor, a partner, another witness) who
// wants to add its own signature to each OBSIGNIA batch after checking it.
//
//   node cosign.mjs keygen
//       Prints a new Ed25519 key. Keep the private key secret; send the public key to KAELUM
//       (info@kaelumtechnologies.com) to be registered as a co-signer.
//
//   OBSIGNIA_COSIGNER_KEY=<private key> node cosign.mjs
//       Checks every batch after the last one you co-signed (signature against the keys in keys/,
//       the link to the previous batch, the anchor digest and each RFC 3161 timestamp to its
//       pinned root) and only then signs it. A batch that fails any check is never signed.
//       Progress is kept in cosign-state.json.
import fs from 'node:fs';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { makeVerifier, canonical } from './lib/obsignia-verify.mjs';

const ENDPOINT = process.env.OBSIGNIA_ENDPOINT || 'https://kaelum.app/api/apps/68be92c2e8f4f1372ccb3500/functions/integrityApi';
const APP_ID = '68be92c2e8f4f1372ccb3500';
const { subtle } = globalThis.crypto;
const kidOf = async (x) => Buffer.from(await subtle.digest('SHA-256', Buffer.from(x, 'base64url'))).toString('hex').slice(0, 16);

if (process.argv[2] === 'keygen') {
  const pair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const x = (await subtle.exportKey('jwk', pair.publicKey)).x;
  console.log(`Key id:      ${await kidOf(x)}\nPublic key:  ${x}\nPrivate key: ${Buffer.from(await subtle.exportKey('pkcs8', pair.privateKey)).toString('base64')}\n\nSend only the public key to KAELUM. Store the private key as a secret.`);
  process.exit(0);
}

const secret = process.env.OBSIGNIA_COSIGNER_KEY;
if (!secret) { console.error('Set OBSIGNIA_COSIGNER_KEY, or run: node cosign.mjs keygen'); process.exit(2); }
const pkcs8 = Buffer.from(secret, 'base64');
const exportable = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
const kid = await kidOf((await subtle.exportKey('jwk', exportable)).x);
const privateKey = await subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);

async function call(body) {
  const res = await fetch(ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-App-Id': APP_ID }, body: JSON.stringify(body) });
  return { status: res.status, data: await res.json().catch(() => ({})) };
}

const v = makeVerifier({ crypto: globalThis.crypto, pkijs, asn1js });
const keys = Object.fromEntries((fs.existsSync('keys') ? fs.readdirSync('keys') : []).map((f) => { const k = JSON.parse(fs.readFileSync(`keys/${f}`, 'utf8')); return [k.kid, k]; }));
const stateFile = 'cosign-state.json';
const state = fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile, 'utf8')) : null;

const registered = (await call({ action: 'keys' })).data.cosigners || [];
if (!registered.some((c) => c.kid === kid)) { console.error(`Key ${kid} is not registered as an OBSIGNIA co-signer yet.`); process.exit(1); }

// First run: start from the last batch this repository's witness has recorded.
const witnessState = fs.existsSync('state.json') ? JSON.parse(fs.readFileSync('state.json', 'utf8')) : {};
let last = state || { lastToSeq: Math.max(0, (witnessState.lastToSeq || 0)), lastAnchorDigest: witnessState.lastAnchorDigest || null };
if (!state) { const prior = (await call({ action: 'sths', afterToSeq: 0, limit: 200 })).data.sths || []; const before = prior.filter((s) => s.sth.toSeq < (witnessState.lastToSeq || 0)).pop(); last = before ? { lastToSeq: before.sth.toSeq, lastAnchorDigest: before.sth.anchorDigest } : { lastToSeq: 0, lastAnchorDigest: null }; }

const { data } = await call({ action: 'sths', afterToSeq: last.lastToSeq, limit: 200 });
let signed = 0;
for (const s of data.sths || []) {
  const sth = s.sth; const where = `batch ${sth.anchorId} (entries ${sth.fromSeq} to ${sth.toSeq})`;
  const checks = {
    signature: Boolean(keys[sth.kid]) && await v.verifySth(sth, s.sthSignature, keys[sth.kid].publicKeyJwk),
    digest: (await v.anchorDigest(sth.merkleRoot, sth.headEntryHash, sth.prevAnchorDigest || null)) === sth.anchorDigest,
    link: last.lastAnchorDigest ? sth.prevAnchorDigest === last.lastAnchorDigest && sth.fromSeq === last.lastToSeq + 1 : true,
    timestamps: false,
  };
  for (const w of s.witnesses || []) if ((await v.verifyTimestamp(w.tokenBase64, sth.anchorDigest)).ok) checks.timestamps = true;
  const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
  if (failed.length) { console.error(`Not co-signing ${where}: failed ${failed.join(', ')}. Stopping.`); process.exit(1); }
  if (!(s.cosignatures || []).some((c) => c.kid === kid)) {
    const signature = Buffer.from(await subtle.sign({ name: 'Ed25519' }, privateKey, new TextEncoder().encode(canonical(sth)))).toString('base64');
    const r = await call({ action: 'cosign', kid, anchorId: sth.anchorId, signature });
    if (r.status >= 400) { console.error(`KAELUM did not accept the co-signature for ${where}: ${r.data.error}`); process.exit(1); }
    signed += 1; console.log(`Co-signed ${where}`);
  }
  last = { lastToSeq: sth.toSeq, lastAnchorDigest: sth.anchorDigest };
  fs.writeFileSync(stateFile, JSON.stringify({ ...last, kid, updatedAt: new Date().toISOString() }, null, 2) + '\n');
}
console.log(signed ? `${signed} batch(es) co-signed with key ${kid}.` : 'Nothing new to co-sign.');
