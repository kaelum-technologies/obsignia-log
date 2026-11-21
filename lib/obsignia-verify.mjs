/**
 * OBSIGNIA verifier (shared). One source used by:
 *   - the /verify page, so a visitor checks a proof in their own browser;
 *   - integrityApi, to check timestamp tokens before an anchor is accepted;
 *   - the public witness (the obsignia-log repository: witness.mjs and verify.mjs).
 *
 * It depends only on WebCrypto plus pkijs and asn1js, which are passed in, so the same
 * code runs in a browser, Node 20+ and Deno.
 *
 * What it checks:
 *   entryHash   SHA-256 of "seq|payloadHash|prevHash|createdAt"
 *   Merkle v1   leaf = SHA-256("seq|entryHash"); node = SHA-256(leftHex + rightHex); odd node paired with itself
 *   Merkle v2   leaf = SHA-256(0x00 || "seq|entryHash"); node = SHA-256(0x01 || left || right); odd node promoted
 *   anchor      anchorDigest = SHA-256(0x02 || merkleRoot || headEntryHash || prevAnchorDigest), all raw 32 bytes,
 *               prevAnchorDigest is 32 zero bytes when there is none
 *   STH         Ed25519 signature over the canonical JSON of the signed tree head
 *   receipt     Ed25519 signature over the canonical JSON of a signed receipt (same key as the STH)
 *   balances    Merkle sum tree: leaf = SHA-256(0x10 || id || u64 balanceMinor);
 *               node = SHA-256(0x11 || left || u64 leftSum || right || u64 rightSum); odd node promoted
 *   RFC 3161    token granted, CMS signature valid, message imprint equals the expected digest, signer
 *               certificate has the time-stamping purpose and was valid at genTime, and the certificate
 *               chain ends at a pinned root key (DigiCert Trusted Root G4 or Sectigo Public Time Stamping Root R46)
 */

// SHA-256 of each root's SubjectPublicKeyInfo, taken from the roots the authorities publish:
// cacerts.digicert.com, crt.sectigo.com and freetsa.org/files/cacert.pem. FreeTSA timestamped
// the first anchor (July 2026), before DigiCert became the primary authority.
export const TSA_ROOT_PINS = {
  '59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c': 'DigiCert Trusted Root G4',
  'a4db8668c6796ebf476ddc5ace453a9260dbd4dbb09f51ecec9a839003824795': 'Sectigo Public Time Stamping Root R46',
  '52c54ba340885605314daa1857c8763b94087d05c636092938d4e2d1818e99b5': 'Free TSA Root CA',
};

const TIME_STAMPING_EKU = '1.3.6.1.5.5.7.3.8';
const EKU_OID = '2.5.29.37';

export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().filter((k) => value[k] !== undefined).map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value === undefined ? null : value);
}

export function makeVerifier({ crypto, pkijs, asn1js }) {
  const enc = new TextEncoder();
  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const fromHex = (h) => Uint8Array.from(String(h).match(/.{2}/g).map((p) => parseInt(p, 16)));
  const fromB64 = (s) => Uint8Array.from(atob(String(s).replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
  const sha256 = async (bytes) => hex(await crypto.subtle.digest('SHA-256', bytes));
  const sha256Text = (s) => sha256(enc.encode(s));
  const ZERO32 = new Uint8Array(32);

  if (pkijs) {
    try { pkijs.setEngine('obsignia', new pkijs.CryptoEngine({ name: 'obsignia', crypto })); } catch (_) { /* engine already set */ }
  }

  const entryHash = (e) => sha256Text(`${e.seq}|${e.payloadHash}|${e.prevHash}|${e.createdAt}`);
  const leaf = (version, e) => version === 2
    ? sha256(concat(Uint8Array.of(0x00), enc.encode(`${e.seq}|${e.entryHash}`)))
    : sha256Text(`${e.seq}|${e.entryHash}`);
  const node = (version, l, r) => version === 2
    ? sha256(concat(Uint8Array.of(0x01), fromHex(l), fromHex(r)))
    : sha256Text(l + r);

  async function foldPath(version, leafHash, path) {
    let h = leafHash;
    for (const step of path || []) h = step.position === 'left' ? await node(version, step.hash, h) : await node(version, h, step.hash);
    return h;
  }

  const anchorDigest = (merkleRoot, headEntryHash, prevAnchorDigest) =>
    sha256(concat(Uint8Array.of(0x02), fromHex(merkleRoot), fromHex(headEntryHash), prevAnchorDigest ? fromHex(prevAnchorDigest) : ZERO32));

  async function verifySth(sth, signatureB64, publicKeyJwk) {
    try {
      const key = await crypto.subtle.importKey('jwk', { kty: 'OKP', crv: 'Ed25519', x: publicKeyJwk.x }, { name: 'Ed25519' }, false, ['verify']);
      return await crypto.subtle.verify({ name: 'Ed25519' }, key, fromB64(signatureB64), enc.encode(canonical(sth)));
    } catch (_) { return false; }
  }

  // A signed receipt is issued when an entry is written, so its holder keeps proof that the
  // entry existed even if it were later removed from the ledger.
  async function verifyReceipt(signed, keys = []) {
    const r = signed && signed.receipt;
    if (!r) return { ok: false, note: 'No receipt.' };
    const key = keys.find((k) => k.kid === r.kid);
    if (!key) return { ok: false, note: 'The signing key is not in the published list.' };
    const ok = await verifySth(r, signed.signature, key.publicKeyJwk);
    return { ok, note: ok ? `Signed by key ${r.kid}.` : 'The signature does not match the receipt.' };
  }

  // Daily balance commitment (Merkle sum tree). Balances are in minor units (1/100 KAE).
  const u64 = (n) => { const b = new Uint8Array(8); let v = BigInt(n); for (let i = 7; i >= 0; i--) { b[i] = Number(v & 255n); v >>= 8n; } return b; };
  const balanceLeaf = (id, minor) => sha256(concat(Uint8Array.of(0x10), fromHex(id), u64(minor)));
  const balanceNode = (l, ls, r, rs) => sha256(concat(Uint8Array.of(0x11), fromHex(l), u64(ls), fromHex(r), u64(rs)));
  async function foldBalance(leafRow, path) {
    let h = await balanceLeaf(leafRow.id, leafRow.balanceMinor);
    let s = BigInt(leafRow.balanceMinor);
    for (const step of path || []) {
      const ss = BigInt(step.sum);
      if (ss < 0n) return null;
      h = step.position === 'left' ? await balanceNode(step.hash, ss, h, s) : await balanceNode(h, s, step.hash, ss);
      s += ss;
    }
    return { root: h, totalMinor: s.toString() };
  }
  // Checks a balance proof and that the committed root is the one recorded on OBSIGNIA. The ledger
  // reference carries the root, and the root fixes every sum beneath it, including the total.
  async function verifyBalanceProof(p) {
    const folded = await foldBalance(p.leaf, p.path);
    const out = [];
    out.push({ name: 'Your balance is included in the daily total', ok: Boolean(folded) && folded.root === p.root && folded.totalMinor === String(p.totalMinor), detail: `${p.date}: ${(Number(p.leaf.balanceMinor) / 100).toFixed(2)} KAE` });
    out.push({ name: 'The commitment is the one recorded on OBSIGNIA', ok: String(p.eventRef || '') === `BALANCE-${p.date}-${p.root}`, detail: p.eventRef || '' });
    return out;
  }

  async function spkiHash(cert) { return sha256(cert.subjectPublicKeyInfo.toSchema().toBER(false)); }
  function sameName(a, b) { try { return hex(a.toSchema().toBER(false)) === hex(b.toSchema().toBER(false)); } catch (_) { return false; } }
  function commonName(name) {
    const cn = (name?.typesAndValues || []).find((tv) => tv.type === '2.5.4.3');
    return cn ? cn.value.valueBlock.value : '';
  }

  /**
   * Verify an RFC 3161 time-stamp. Accepts either the full TimeStampResp or just the token.
   * Returns { ok, genTime, tsa, root, serialNumber, checks: { granted, imprint, signature, purpose, validity, chain }, note }.
   */
  async function verifyTimestamp(tokenB64, expectedDigestHex, pins = TSA_ROOT_PINS) {
    const checks = { granted: false, imprint: false, signature: false, purpose: false, validity: false, chain: false };
    const fail = (note) => ({ ok: false, checks, note });
    if (!pkijs || !asn1js) return fail('Certificate checks need pkijs and asn1js.');
    let contentInfo;
    try {
      const der = fromB64(tokenB64);
      const parsed = asn1js.fromBER(der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength));
      if (parsed.offset === -1) return fail('The token is not valid DER.');
      // TimeStampResp is SEQUENCE { PKIStatusInfo SEQUENCE, token ContentInfo }. ContentInfo starts with an OID.
      const first = parsed.result.valueBlock.value[0];
      if (first instanceof asn1js.Sequence) {
        const resp = new pkijs.TimeStampResp({ schema: parsed.result });
        if (resp.status.status !== 0 && resp.status.status !== 1) return fail(`The authority did not grant the request (status ${resp.status.status}).`);
        if (!resp.timeStampToken) return fail('The response carries no token.');
        contentInfo = resp.timeStampToken;
      } else {
        contentInfo = new pkijs.ContentInfo({ schema: parsed.result });
      }
      checks.granted = true;
    } catch (e) { return fail(`The token could not be parsed: ${e.message}`); }

    let signedData; let tst;
    try {
      signedData = new pkijs.SignedData({ schema: contentInfo.content });
      const econtent = signedData.encapContentInfo.eContent;
      const tstBytes = econtent.valueBlock.valueHexView || new Uint8Array(econtent.valueBlock.valueHex);
      tst = pkijs.TSTInfo.fromBER(tstBytes);
    } catch (e) { return fail(`The token content could not be read: ${e.message}`); }

    const imprint = hex(tst.messageImprint.hashedMessage.valueBlock.valueHexView || tst.messageImprint.hashedMessage.valueBlock.valueHex);
    checks.imprint = imprint.toLowerCase() === String(expectedDigestHex).toLowerCase();
    const genTime = tst.genTime instanceof Date ? tst.genTime : new Date(tst.genTime);
    const serialNumber = hex(tst.serialNumber.valueBlock.valueHexView || tst.serialNumber.valueBlock.valueHex);

    let signer = null;
    try {
      // pkijs would otherwise ask for the original timestamped data, which we never hold (only its
      // digest). As plain data it still checks the CMS signature and the signed messageDigest of the
      // TSTInfo bytes; the imprint inside TSTInfo is checked separately above.
      signedData.encapContentInfo.eContentType = '1.2.840.113549.1.7.1';
      const result = await signedData.verify({ signer: 0, checkChain: false, extendedMode: true });
      checks.signature = Boolean(result.signatureVerified);
      signer = result.signerCertificate || null;
    } catch (e) { checks.signature = false; }

    const certs = (signedData.certificates || []).filter((c) => c instanceof pkijs.Certificate);
    if (signer) {
      const eku = (signer.extensions || []).find((x) => x.extnID === EKU_OID);
      checks.purpose = Boolean(eku && eku.parsedValue && (eku.parsedValue.keyPurposes || []).includes(TIME_STAMPING_EKU));
      checks.validity = signer.notBefore.value <= genTime && genTime <= signer.notAfter.value;
      // Walk up: each certificate must be signed by its issuer, ending at a pinned root key.
      let current = signer; let root = null;
      for (let depth = 0; depth < 6 && current; depth++) {
        const h = await spkiHash(current);
        if (pins[h]) { root = pins[h]; break; }
        const issuer = certs.find((c) => c !== current && sameName(c.subject, current.issuer));
        if (!issuer) break;
        let signedByIssuer = false;
        try { signedByIssuer = await current.verify(issuer); } catch (_) { signedByIssuer = false; }
        if (!signedByIssuer) break;
        current = issuer;
      }
      checks.chain = Boolean(root);
      const ok = Object.values(checks).every(Boolean);
      const failed = Object.entries(checks).filter(([, v]) => !v).map(([k]) => k);
      return { ok, genTime: genTime.toISOString(), tsa: commonName(signer.subject), root, serialNumber, checks, note: ok ? `Signed by ${commonName(signer.subject)}, chained to ${root}.` : `Failed checks: ${failed.join(', ')}.` };
    }
    return { ok: false, genTime: genTime.toISOString(), serialNumber, checks, note: 'The signer certificate was not found in the token.' };
  }

  /**
   * Check a full OBSIGNIA proof bundle (formatVersion 2 or 3) without trusting the server.
   * keys: the published key list [{ kid, publicKeyJwk }]. Returns a list of named checks.
   */
  async function verifyBundle(bundle, keys = []) {
    const out = [];
    const add = (name, ok, detail = '') => out.push({ name, ok: Boolean(ok), detail });
    const e = bundle.entry;
    add('Entry hash matches its contents', (await entryHash(e)) === e.entryHash);
    if (bundle.chainLink?.previousEntryHash !== undefined) add('Links to the entry before it', e.seq === 1 ? e.prevHash === '' : e.prevHash === bundle.chainLink.previousEntryHash);
    const ip = bundle.inclusionProof; const a = bundle.anchor;
    if (!ip || !a) { add('Included in a timestamped batch', false, 'Not yet anchored; the timestamp is added at the next scheduled anchor.'); return out; }
    const version = Number(ip.merkleVersion) === 2 ? 2 : 1;
    const lf = await leaf(version, e);
    const root = await foldPath(version, lf, ip.path);
    add('Included in the batch (Merkle proof)', root === a.merkleRoot, `Merkle format v${version}`);
    let timestamped = a.merkleRoot;
    if (a.anchorDigest) {
      const d = await anchorDigest(a.merkleRoot, a.headEntryHash, a.prevAnchorDigest || null);
      add('Batch linked to the previous batch', d === a.anchorDigest);
      timestamped = a.anchorDigest;
    }
    if (bundle.sth) {
      const key = keys.find((k) => k.kid === bundle.sth.kid);
      const sthMatches = bundle.sth.merkleRoot === a.merkleRoot && (!a.anchorDigest || bundle.sth.anchorDigest === a.anchorDigest);
      add('Signed by KAELUM’s published key', Boolean(key) && sthMatches && await verifySth(bundle.sth, bundle.sthSignature, key.publicKeyJwk), key ? `Key ${key.kid}` : 'Key not found in the published list');
    }
    const witnesses = (a.witnesses && a.witnesses.length) ? a.witnesses : (a.rfc3161TokenBase64 ? [{ name: 'Timestamp authority', tokenBase64: a.rfc3161TokenBase64 }] : []);
    for (const w of witnesses) {
      const r = await verifyTimestamp(w.tokenBase64, timestamped);
      add(`Independently timestamped (${r.tsa || w.name})`, r.ok, r.ok ? `${r.genTime}, ${r.root}` : r.note);
    }
    if (bundle.signedReceipt) {
      const r = bundle.signedReceipt.receipt || {};
      const sig = await verifyReceipt(bundle.signedReceipt, keys);
      add('Signed receipt matches this entry', sig.ok && r.eventRef === e.eventRef && r.seq === e.seq && r.entryHash === e.entryHash, sig.note);
    }
    return out;
  }

  return { canonical, entryHash, leaf, node, foldPath, anchorDigest, verifySth, verifyTimestamp, verifyBundle, verifyReceipt, balanceLeaf, balanceNode, foldBalance, verifyBalanceProof, hex, fromHex, sha256 };
}
