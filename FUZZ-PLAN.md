# Cross-SDK differential fuzzing — moved

This plan now lives in its own repo so the harness can grow without
dragging this worker's release cadence:

- **Repo**: [Calgooon/bsv-fuzz](https://github.com/Calgooon/bsv-fuzz) (private)
- **Local**: `~/bsv/bsv-fuzz/`
- **Plan doc**: `~/bsv/bsv-fuzz/PLAN.md`
- **Findings log**: `~/bsv/bsv-fuzz/FINDINGS.md`

The harness is complementary to — not a replacement for — this repo's
`PARITY-CLAIMS.md` + `tests/parity/`. Static fixtures pin N known
inputs byte-exact; the fuzz harness extends that to an arbitrary
number of random inputs across the three SDKs (bsv-rs, @bsv/sdk, go-sdk).

Status as of 2026-04-21: Phase 0 scaffold shipped, sha256 three-way
byte-exact on 256 random inputs. Tier 1 (BRC-42, sighash, script
round-trip) next.
