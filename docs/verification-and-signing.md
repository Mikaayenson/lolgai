# Verification and signing

Catalog tools carry `Coverage.VerificationLevel`:

| Level | Meaning |
| --- | --- |
| `observed` | Primary binary or documented install footprint empirically verified on at least one lab host |
| `documented` | Official docs / vendor guidance only; not confirmed on a lab PATH |
| `unverified` | Placeholder or disputed entry (target: zero in the published catalog) |

## Signing fields

Prefer endpoint-observable signer identity collected from a lab host or official packaging docs:

- macOS: `SigningId`, `TeamId`, `Authority`, `BundleId`
- Windows: `Subject`, `Thumbprint`, `CertificateCN`, Authenticode depth
- Set `UsableForAttribution: false` when signing is ad hoc, partial, or a shared host (e.g. VS Code)

Do not claim PE hashes or signing depth without measurement. Prefer values from
official packaging docs or direct inspection of the binary on a system you control.

Do not commit raw host inventories, probe dumps, or other lab evidence into this repository.
