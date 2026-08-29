# Audit follow-ups

Deferred items surfaced by the audit. The domain-separation and salt-binding
items have since been settled against the round-3 C reference (vole-sd main +
PRs #211, #214) and verified C == python byte-identical. The two items below
still need a spec-author call or are optional hardening.

## Resolved (pinned against the C reference)
- [x] **Salt binding.** The full salt is now bound into `hash_com` (after the
  per-repetition subhashes) instead of `hash_aux`, on both prover and verifier,
  per Nicolas. This commits all lambda bits and removes the low-bit
  malleability. Mirrors vole-sd PR #214; C == python byte-identical. Spec text
  still needs the matching edit (`bavc.tex` hCom / `blc.tex` hAux) -- flagged
  on #214.
- [x] **`_domain_sep_ptx` bit-layout.** Now `ptx = (salt & ~(2^theta - 1)) | tweak`
  (full salt, tweak overlaid on the low theta bits), replacing the old
  `Trunc_theta(salt) || MapToBits(tweak)` layout. Mirrors C #211; pinned
  byte-identical vs the C reference (cat1/3/5).
- [x] **cat3 `Enc` byte convention.** The `key||0^64` / `LSB_192` mapping in
  `_cat3_enc` is verified byte-identical vs the C reference (cat3-short).

## Still open -- needs spec-author input
- [ ] **`num_cchk_pairs` basis.** `params.py` uses `ceil8(kappa*tau + 16)` but the
  spec's consistency-check region is `lambda + B`. They coincide for all six
  shipped sets only because `kappa*tau ~= lambda`. Confirm which is authoritative
  and, if it should be `lambda + B`, change the formula (would change KATs).

## Still open -- robustness hardening (optional, low severity)
- [ ] **pk length check.** `unpack_pkey` does not length-check `pkey`; a short
  public key hits a fixed-size slice-assign in `rsd_public_key_times_challenge`.
  pk is trusted input, so low severity, but `verify`/keygen could fail closed.
