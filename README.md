# OBSIGNIA public witness

OBSIGNIA is the integrity ledger of KAELUM, the Ai-native commerce currency platform built by Kaelum Technologies Ltd. Every recorded event is hash-chained, gathered into batches, timestamped by two independent timestamp authorities and signed with a published Ed25519 key.

This repository is the independent witness. Once an hour, a GitHub Action:

1. Fetches each new signed batch from KAELUM.
2. Checks it without trusting KAELUM: the Ed25519 signature against the key recorded here, the link to the previous batch, and each RFC 3161 timestamp down to the authority's own root certificate.
3. Records what it has checked in this repository.

Git history is public and cannot be quietly changed. If a batch that was already witnessed is later withdrawn, altered or replaced, if a recorded key changes, if a new key appears without an endorsement from a key already recorded here, or if a new batch does not link to the last one, the run fails and opens an issue labelled `obsignia-alarm`.

Each run that records something also publishes a signed build provenance attestation (Sigstore, through GitHub artifact attestations) for `state.json`. That places the witnessed state in a public transparency log outside both KAELUM and this repository. Check one with `gh attestation verify state.json --repo kaelum-technologies/obsignia-log`.

## Keys and custody

The OBSIGNIA signing key can be rotated, and can be moved out of the KAELUM platform into a separate signer that will only sign a batch extending the history it has already signed. Every new key carries an endorsement: a statement naming the new key, signed by the key it replaces. This witness records the endorsement in `keys/` and refuses any new key that does not have one.

## Check a receipt yourself

Download a proof bundle from https://kaelum.app/verify, then:

```
npm install
node verify.mjs obsignia-proof-<reference>.json
```

The verifier uses only the keys recorded in `keys/` and the timestamp authorities' pinned root keys. It needs no account and makes no request to KAELUM.

## What is here

| Path | Contents |
|---|---|
| `log/` | Every witnessed batch: the signed tree head, its signature, both timestamp tokens and the checks that passed |
| `keys/` | KAELUM's OBSIGNIA public keys, as first witnessed, with custody and endorsement |
| `cosigners/` | Independent co-signers' public keys, as first witnessed |
| `attestations/` | Signed attestations of ledger figures, checked against the keys in `keys/` |
| `legacy/anchors.json` | Batches from before signed tree heads (July to November 2026), frozen when this witness started |
| `state.json` | The last batch witnessed |
| `lib/obsignia-verify.mjs` | The verifier, the same code the KAELUM verify page runs in the browser |

## Run your own witness

Anyone can run an identical witness, so trust does not rest on this repository either:

1. Fork this repository (or copy it into a new one).
2. Delete `state.json`, `log/`, `keys/`, `cosigners/`, `attestations/` and `legacy/` so your witness starts fresh.
3. Enable GitHub Actions in the fork. The workflow runs hourly and records its own history.

Two independent witnesses that agree are much stronger evidence than one. If they ever disagree, at least one of them has been shown a different history.

## Co-sign each batch

A registered co-signer adds its own Ed25519 signature to each batch after checking it:

```
npm install
node cosign.mjs keygen                      # once: send the public key to info@kaelumtechnologies.com
OBSIGNIA_COSIGNER_KEY=<private key> node cosign.mjs
```

`cosign.mjs` checks every batch (signature, link, digest and timestamps) before signing it, and stops at the first batch that fails. Run it on a schedule in your own fork. Co-signatures appear in every proof bundle and are checked by `verify.mjs` and the KAELUM verify page.

## Timestamp authorities

Roots are pinned by the SHA-256 of their public key, taken from the certificates each authority publishes:

| Authority | Root |
|---|---|
| DigiCert | DigiCert Trusted Root G4 |
| Sectigo | Sectigo Public Time Stamping Root R46 |
| Free TSA | Free TSA Root CA (first batch only, July 2026) |

## What this proves, and what it does not

It proves that a recorded event existed, unaltered, at the time two independent authorities witnessed it, and that KAELUM has not rewritten a batch since. It does not prove that a recorded value was correct when it was written.

KAELUM is pre-launch and is working towards the appropriate regulatory permissions before it takes any customer funds.

https://kaelum.app · info@kaelumtechnologies.com
