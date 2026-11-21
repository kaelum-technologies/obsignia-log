// OBSIGNIA public witness.
// Runs hourly in GitHub Actions. It pulls KAELUM's signed tree heads, checks every one
// independently (Ed25519 signature, link to the previous batch, and each RFC 3161 timestamp
// down to the authority's pinned root), and commits what it has checked to this repository.
// Git history is public and append-only, so a later rewrite of an already-witnessed batch,
// a changed key or a broken link is caught here and raised as a failed run and an issue.
import fs from 'node:fs';
import path from 'node:path';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { makeVerifier, canonical } from './lib/obsignia-verify.mjs';

const ENDPOINT = process.env.OBSIGNIA_ENDPOINT || 'https://kaelum.app/api/apps/68be92c2e8f4f1372ccb3500/functions/integrityApi';
const APP_ID = '68be92c2e8f4f1372ccb3500';
const v = makeVerifier({ crypto: globalThis.crypto, pkijs, asn1js });
const alarms = [];
const alarm = (msg) => { alarms.push(msg); console.error('ALARM:', msg); };
const readJson = (f, d) => (fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : d);
const writeJson = (f, o) => { fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, JSON.stringify(o, null, 2) + '\n'); };

async function call(body) {
  const res = await fetch(ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-App-Id': APP_ID }, body: JSON.stringify(body) });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { throw new Error(`Endpoint returned non-JSON (HTTP ${res.status})`); }
  return { status: res.status, data };
}

const state = readJson('state.json', { lastToSeq: 0, lastAnchorId: null, lastAnchorDigest: null, witnessedBatches: 0 });

// 1. Earlier (format 1) anchors: freeze them once, then confirm on every run that none has changed.
const att = await call({ action: 'attestations' });
const anchors = att.data.anchors || [];
const legacyFile = 'legacy/anchors.json';
let legacy = readJson(legacyFile, null);
if (!legacy) {
  legacy = [];
  for (const a of anchors.filter((x) => x.status === 'CONFIRMED' && !x.anchorDigest).sort((x, y) => x.toSeq - y.toSeq)) {
    const r = await v.verifyTimestamp(a.tsaProof, a.merkleRoot);
    legacy.push({ anchorId: a.anchorId, fromSeq: a.fromSeq, toSeq: a.toSeq, merkleRoot: a.merkleRoot, timestamp: r.genTime || null, authority: r.tsa || null, root: r.root || null, verified: r.ok });
    if (!r.ok) alarm(`Earlier anchor ${a.anchorId} did not verify: ${r.note}`);
  }
  writeJson(legacyFile, legacy);
  console.log(`Froze ${legacy.length} earlier anchors.`);
} else {
  const byId = new Map(anchors.map((a) => [a.anchorId, a]));
  for (const l of legacy) { const now = byId.get(l.anchorId); if (now && now.merkleRoot !== l.merkleRoot) alarm(`Earlier anchor ${l.anchorId} changed its Merkle root.`); }
}

// 2. Keys: a published key must never change once witnessed.
const keysRes = await call({ action: 'keys' });
if (keysRes.status >= 400 || !Array.isArray(keysRes.data.keys)) {
  console.log('Signed tree heads are not published yet. Nothing further to witness.');
} else {
  for (const k of keysRes.data.keys) {
    const f = `keys/${k.kid}.json`; const seen = readJson(f, null);
    if (seen && canonical(seen.publicKeyJwk) !== canonical(k.publicKeyJwk)) alarm(`Key ${k.kid} changed after it was witnessed.`);
    if (!seen) { writeJson(f, { kid: k.kid, alg: k.alg, publicKeyJwk: k.publicKeyJwk, activatedAt: k.activatedAt, firstWitnessedAt: new Date().toISOString() }); console.log(`New key witnessed: ${k.kid}`); }
  }
  // Nothing already witnessed may be withdrawn, altered or replaced.
  const walk = (d) => (fs.existsSync(d) ? fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(`${d}/${e.name}`) : [e.name])) : []);
  const witnessedIds = new Set(walk('log').map((f) => (f.match(/-(ANCH-.+)\.json$/) || [])[1]).filter(Boolean));
  const windowCovers = anchors.length < 200 || anchors.some((a) => state.lastIssuedAt && a.createdAt <= state.lastIssuedAt);
  if (state.lastAnchorId && windowCovers && !anchors.some((a) => a.anchorId === state.lastAnchorId && a.status === 'CONFIRMED' && a.anchorDigest === state.lastAnchorDigest)) {
    alarm(`The last witnessed batch ${state.lastAnchorId} is no longer published as it was witnessed. It has been withdrawn or altered.`);
  }
  for (const a of anchors) {
    if (a.status === 'CONFIRMED' && a.anchorDigest && a.toSeq <= state.lastToSeq && !witnessedIds.has(a.anchorId)) {
      alarm(`Batch ${a.anchorId} covers entries ${a.fromSeq} to ${a.toSeq}, which were already witnessed in a different batch. History may have been rewritten.`);
    }
  }
  const keys = Object.fromEntries(fs.existsSync('keys') ? fs.readdirSync('keys').map((f) => { const k = readJson(`keys/${f}`); return [k.kid, k]; }) : []);

  // 3. Signed tree heads after the last one witnessed.
  const { data } = await call({ action: 'sths', afterToSeq: state.lastToSeq, limit: 200 });
  for (const s of alarms.length ? [] : data.sths || []) {
    const sth = s.sth; const where = `batch ${sth.anchorId} (entries ${sth.fromSeq} to ${sth.toSeq})`;
    const checks = {};
    checks.signature = Boolean(keys[sth.kid]) && await v.verifySth(sth, s.sthSignature, keys[sth.kid].publicKeyJwk);
    checks.digest = (await v.anchorDigest(sth.merkleRoot, sth.headEntryHash, sth.prevAnchorDigest || null)) === sth.anchorDigest;
    if (state.lastAnchorDigest) {
      checks.link = sth.prevAnchorDigest === state.lastAnchorDigest && sth.fromSeq === state.lastToSeq + 1;
    } else {
      const before = legacy.find((l) => l.toSeq === sth.fromSeq - 1);
      checks.link = before ? sth.prevAnchorDigest === before.merkleRoot : sth.fromSeq === 1 && !sth.prevAnchorDigest;
    }
    const witnessed = [];
    for (const w of s.witnesses || []) { const r = await v.verifyTimestamp(w.tokenBase64, sth.anchorDigest); witnessed.push({ authority: r.tsa || w.name, root: r.root || null, genTime: r.genTime || null, verified: r.ok, note: r.note, tokenBase64: w.tokenBase64 }); }
    checks.timestamps = witnessed.some((w) => w.verified);
    const failed = Object.entries(checks).filter(([, ok]) => !ok).map(([k]) => k);
    if (failed.length) { alarm(`${where} failed: ${failed.join(', ')}.`); break; }
    const d = new Date(sth.issuedAt);
    writeJson(`log/${d.getUTCFullYear()}/${String(d.getUTCMonth() + 1).padStart(2, '0')}/${String(sth.toSeq).padStart(9, '0')}-${sth.anchorId}.json`, { sth, sthSignature: s.sthSignature, witnesses: witnessed, checks, witnessedAt: new Date().toISOString() });
    Object.assign(state, { lastToSeq: sth.toSeq, lastAnchorId: sth.anchorId, lastAnchorDigest: sth.anchorDigest, lastIssuedAt: sth.issuedAt, witnessedBatches: state.witnessedBatches + 1 });
    console.log(`Witnessed ${where}: ${witnessed.filter((w) => w.verified).map((w) => w.root).join(' + ')}`);
  }
}

writeJson('state.json', { ...state, lastRun: new Date().toISOString() });
if (alarms.length) { fs.writeFileSync('ALARM.md', `# OBSIGNIA witness alarm\n\n${new Date().toISOString()}\n\n${alarms.map((a) => `- ${a}`).join('\n')}\n`); process.exit(1); }
