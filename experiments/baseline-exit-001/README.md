# BASELINE-EXIT-001

Read the immutable [preregistration](PREREGISTRATION.md) first. This directory
contains a local security-mechanism comparison, not a production OAuth server
or a commercial provider-exit test. Production OpenLine is imported unchanged.

From the repository root:

```bash
.venv/bin/python -m pip install -r experiments/baseline-exit-001/requirements.txt
cd experiments/baseline-exit-001
../../.venv/bin/python -m unittest test_protocol -v
cd ../..
.venv/bin/python experiments/baseline-exit-001/run.py --out /tmp/baseline-exit-new-run
.venv/bin/python experiments/baseline-exit-001/verify.py /tmp/baseline-exit-new-run --out /tmp/baseline-exit-new-verification.json
```

The runner refuses to overwrite an output directory and checks the frozen
preregistration bytes. It generates fresh ephemeral keys, kills/reaps Provider
A, removes A's unique directory before starting B, stops all processes at
completion, and destroys its private temporary directory. Only public trust
material and short-lived local simulation credentials enter evidence. Current
authorization checks use PyJWT's real clock; the offline verifier evaluates
signed history at recorded observation times. No signature/TLS verification is
disabled for installation or live authorization.

`protocol.py` defines the JOSE and exchange profiles; `service.py` is the
receiver and authority/AS plumbing; `worker.py` is the provider; `run.py` is the
supervisor; `verify.py` is the fresh offline verifier. The standards references
and explicit nonstandard application claims are enumerated in the registration.

Implementation is committed before the scenario runner starts. An apparatus
failure is preserved with its metadata and never relabeled a passing arm.
Look at REPORT.md and the preserved results for conclusions and timing bounds.
