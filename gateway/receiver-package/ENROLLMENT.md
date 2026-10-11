# Owner Key Enrollment and Rotation

How a receiver pins an owner's root key, and how to rotate it.

## Enrollment (First Time)

**Goal:** The receiver obtains the owner's root public key through a
channel the receiver trusts, and pins it.

**Procedure:**

1. **Owner generates a root keypair.**
   The owner runs the OpenLine Wallet. The Wallet creates an Ed25519
   root keypair on first run. The public key is exported as hex.

2. **Owner transmits the root public key out-of-band.**
   The channel depends on the relationship:
   - **In person / video call:** Owner reads the hex aloud; receiver types it.
   - **Signed email:** Owner emails the hex from a known address; receiver
     verifies the signature (PGP, etc.).
   - **API enrollment:** Owner's server exposes `/openline/root-key`;
     receiver fetches over TLS and pins the certificate.
   - **For Lithic ASA sandbox:** Test owner emails the hex to the
     integrator; integrator pastes into sandbox config.

   **The receiver MUST NOT accept a root key from the worker/agent.**
   The worker is untrusted. The key must come from the owner directly.

3. **Receiver pins the key.**
   ```python
   receiver.pin_owner("owner-principal-id", "hex-of-root-public-key")
   ```
   The `principal_id` is a string the receiver chooses (e.g., the owner's
   email, account ID, or "lithic-test-owner"). It must be unique per owner.

4. **Receiver verifies the pin.**
   Ask the owner to sign a test bundle. Admit it. If `BUNDLE_ADMITTED`,
   the pin is correct. If `BUNDLE_SIGNATURE_INVALID`, the key is wrong.

**Security:** If an attacker substitutes a different root key during
enrollment, they can forge bundles. The out-of-band channel is the
trust root. Choose it carefully.

## Rotation (Owner Changes Key)

**Goal:** The owner retires an old root key and the receiver pins the new one,
without allowing an attacker to substitute.

**Procedure:**

1. **Owner signs a rotation statement with the OLD key.**
   The statement is: `{"rotate_to": "<new-root-key-hex>", "at": "<iso-timestamp>"}`
   signed by the old root key.

2. **Owner transmits the rotation statement + new key out-of-band.**
   Same channel as enrollment (or a new one, but still out-of-band).

3. **Receiver verifies and re-pins.**
   ```python
   # Verify the rotation statement was signed by the OLD pinned key
   old_key = receiver.get_pinned_key("owner-principal-id")
   assert verify_signature(rotation_statement, old_key)
   
   # Pin the new key (replaces the old)
   receiver.pin_owner("owner-principal-id", new_key_hex)
   ```

4. **Old bundles become invalid.**
   Bundles signed by the old key will fail signature verification.
   The owner must issue a new bundle signed by the new key.

**Emergency rotation (old key compromised):**
If the old key is compromised, the owner cannot sign a rotation statement.
The receiver must:
1. Remove the pin: `receiver.unpin_owner("owner-principal-id")`
2. Re-enroll via the full enrollment procedure (out-of-band).
3. Treat all old bundles as invalid until a new bundle is admitted.

## For Lithic ASA Sandbox

**Test enrollment:**
1. Terrynce (test owner) generates a Wallet and exports the root key hex.
2. Terrynce emails the hex to the Lithic integrator (out-of-band).
3. Integrator runs: `receiver.pin_owner("terrynce-test", "<hex>")`
4. Terrynce sends a test bundle. Integrator admits it.

**No production keys.** Sandbox only. No real cardholders.
