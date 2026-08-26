# Warning-time archive release fix

This does not renew or reactivate the expired warning-time calibration profile.

It changes the release gate semantics:

- valid profile, no errors -> PASS
- sole error `profile_expired` -> archive integrity PASS, live standing EXPIRED
- any other error, or expiry plus any other error -> FAIL

The independent verifier itself is unchanged.
The frozen benchmark artifacts are unchanged.
The profile remains expired and may not govern live actions.
