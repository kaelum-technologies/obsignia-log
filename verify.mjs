// Check an OBSIGNIA proof bundle offline: node verify.mjs obsignia-proof-<ref>.json
// Uses the keys this witness has recorded in keys/, so nothing is taken from KAELUM at check time.
import fs from 'node:fs';
import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { makeVerifier } from './lib/obsignia-verify.mjs';

const file = process.argv[2];
if (!file) { console.error('Usage: node verify.mjs <proof-bundle.json>'); process.exit(2); }
const bundle = JSON.parse(fs.readFileSync(file, 'utf8'));
const keys = fs.existsSync('keys') ? fs.readdirSync('keys').map((f) => JSON.parse(fs.readFileSync(`keys/${f}`, 'utf8'))) : [];
const cosigners = fs.existsSync('cosigners') ? fs.readdirSync('cosigners').map((f) => JSON.parse(fs.readFileSync(`cosigners/${f}`, 'utf8'))) : [];
const checks = await makeVerifier({ crypto: globalThis.crypto, pkijs, asn1js }).verifyBundle(bundle, keys, cosigners);
for (const c of checks) console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? `  (${c.detail})` : ''}`);
process.exit(checks.every((c) => c.ok) ? 0 : 1);
