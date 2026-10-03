# Demo keys

These Ed25519 keys authenticate synthetic fixtures only. Private keys are included solely so the offline demo can be regenerated. Never reuse them or this storage design for real data.

In production, each company keeps its private key in its own KMS, HSM or signing service. Meridian receives only the signed payload, detached signature, registered public key/certificate, approval scope and metadata. Meridian's calculation-receipt key is separately controlled and rotated.

A valid signature proves which registered key signed the canonical payload and that the payload was not altered after signing. It does not prove that the signed commercial, financial or legal assertions are true.
