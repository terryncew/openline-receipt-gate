# PR #119 separate read-only review reproduction

Run from the Receipt Gate checkout with Python 3.12+, cryptography installed, and both reviewed Git objects available:

```sh
python experiments/openline-consequence-002/evidence/pr119/reproduce.py
```

The script extracts reference application source and exact PR demo/test objects into an ephemeral directory. It does not switch branches, modify application source, merge, contact an API, or apply the PR. It records raw combined unittest output, Git diff statistics/name status, commit metadata, and SHA-256 hashes for the extracted PR fixtures in this evidence directory.

Reviewed reference: `81db6acb72149df989aac1827e5f621b0873d57b`.
Reviewed PR head: `1749a226b5f77cabc98f04a8655636229e0b11c2`.
If the historical PR head is absent from a new clone, retrieve that exact Git object from the repository before reproducing; a later live PR head is not equivalent.

Read-only search commands and results for the missing original scenario specification are preserved in `scenario-search.log`. An exit code of 1 from `git grep` means no match, not a test failure. This search is limited to the supplied repository and reference history.
