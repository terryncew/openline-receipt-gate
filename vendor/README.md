# Vendored release fixture

`openline-half-life-0.2.0rc5/` is a hash-pinned offline release fixture for
Receipt Gate's deterministic Model Swap, Verified Commit, and Verified
Continuation checks. It contains the pure-Python wheel, a byte-exact extracted
site tree (needed because zipimport cannot resolve the wheel's implicit
namespace package), the exact demo output, public policy keys, the upstream MIT
license, and source metadata.

Run `python scripts/verify_vendored_half_life.py` to verify the local bundle.
CI additionally supplies a separately fetched checkout through
`OLP_HALF_LIFE_SOURCE_ROOT`; the verifier compares the wheel sources, fixture,
policy, license, and exact Git commit against that checkout.

Local integrity is not independent provenance. The external CI comparison is
the provenance witness.
