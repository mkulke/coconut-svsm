# Managed vTPM attestation key (experimental)

The optional `vtpm-ak` build feature adds a directly attested, SVSM-provisioned
attestation key (AK). It complements, rather than replaces, the existing
endorsement key (EK) service. Existing EK manifests and guest-created keys
are unchanged. Enable it with `make FEATURES=vtpm-ak` or pass `-f vtpm-ak`
to `cargo xbuild`.

This is an experimental Coconut extension, not an assigned AMD SVSM service.
The GUID, handle, key template, and manifest layout below are a versioned
interoperability contract for this implementation and require upstream review.

## Discovery and attestation

The AK service GUID is `a6b5b9b0-7491-4f67-98ac-fc12f97b8e43`.
It supports manifest version zero through `SVSM_ATTEST_SINGLE_SERVICE`.
When enabled it is also included in `SVSM_ATTEST_SERVICES`; enumerating all
services therefore also provisions or revalidates the AK, and fails if that
cannot be done. Builds without `vtpm-ak` do not advertise this GUID and reject
single-service requests for it.

The single-service manifest is:

| Offset | Size | Contents |
|--------|------|----------|
| 0 | 4 | Persistent TPM handle, little endian: `0x81010002` |
| 4 | Remaining bytes | Marshaled `TPMT_PUBLIC`, in TPM big-endian wire format |

There is no `TPM2B_PUBLIC` length prefix. The enclosing manifest supplies its
length. No additional NV index is allocated; `TPM2_ReadPublic` on the handle
provides discovery of the same public area through the normal TPM interface.

As with the existing EK service, the SNP report has VMPL zero and
`REPORT_DATA = SHA-512(nonce || manifest)`. For all-service attestation, the
manifest is the complete GUID table, not just the AK entry.

An AK public area obtained using `TPM2_ReadPublic` is not an endorsement.
A verifier must validate the SNP signature and certificate chain, report
freshness, VMPL, launch measurement, TCB and policy; recompute the report-data
binding; and require an SVSM build trusted to implement this extension.
It must then verify the quote signature with the endorsed AK, the quote's
nonce and attestation type, and the requested PCR selection and values
(including the event log when applicable). Binding the public area includes
the key's attributes and signature scheme. EK credential activation is not
needed for this direct-endorsement path.

## Key template and provenance

The AK is an RSA-2048 endorsement-hierarchy primary with SHA-256 names,
RSASSA/SHA-256 signatures, no symmetric algorithm, and the following object
attributes: `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `userWithAuth`,
`restricted`, and `sign`. Its authorization value and policy are empty,
allowing guest software to request quotes. Restricted signing prevents using
it as an unrestricted signing oracle.

The input public area's `unique` field contains the ASCII bytes
`Coconut-SVSM managed AK v1`, domain-separating primary-key derivation from
generic AK templates. This label is public and is not an authorization secret.
The resulting public area's `unique` field contains the generated RSA modulus.
The same endorsement seed and creation inputs recreate the same key.

On every attestation request SVSM:

1. Creates the primary itself using the fixed template.
2. Reads `0x81010002` and compares the complete public area against its freshly
   created primary. A different object is an error and is never evicted.
3. If and only if the handle is absent, persists the primary with
   `TPM2_EvictControl` and verifies its public area by reading it back.
4. Flushes the temporary primary, including on provisioning failures.

These operations run under the existing vTPM lock, excluding guest TPM
commands. SVSM never endorses a key merely because it occupies the handle,
and never uses a cached AK public key. Repeated endorsement incurs primary
recreation cost but does not repeatedly write an existing key to NV.

## Lifecycle and guest ownership

Provisioning is lazy, after firmware has performed `TPM2_Startup` and any
required self-tests. This feature does not take over TPM startup, hierarchy
authorization, or TPM command filtering. It uses empty endorsement authorization
to create the primary and empty owner authorization to initially persist it.
If a guest changes authorization, disables the hierarchy, exhausts TPM
resources, or occupies the handle with another key, attestation can fail.
Existing matching keys need no owner authorization to be read and endorsed.
Failures are returned to the caller and logged; they are not treated as an
absent key or replaced by successful empty manifests.

The handle is an experimental reservation, not a globally allocated handle.
Guest provisioning must avoid using it for unrelated objects. A separate NV
index is unnecessary and would introduce another mutable copy of the metadata.

The guest may evict or change the AK's authorization and may clear the TPM.
SVSM does not prevent these availability changes. Eviction is recovered by
reprovisioning the same primary when authorization allows. `TPM2_Clear`
removes the persistent object but preserves the endorsement seed, so the
same AK can be recreated. `TPM2_ChangeEPS` or remanufacturing changes its
identity. A handle replacement cannot produce quotes valid under the
previously endorsed public key. No stable quote availability or exclusive
use by a particular guest process is promised.

A persistent TPM handle survives TPM shutdown/startup in the same vTPM state.
It does not make an ephemeral VM's state durable. Cross-VM-launch persistence
still requires the existing SVSM persistence feature and its backing storage.
This extension adds no state rollback, cloning, or migration protection.

## Validation

`make test` enables `vtpm-ak` in the default test feature set. Targeted tests:

```shell
cargo test -p svsm --no-default-features --features vtpm-ak --lib vtpm::tcgtpm::ak
```

Command-level tests cover handle collision, error propagation, public-area
readback, malformed responses, and transient cleanup. A host-only test runs
the real TPM reference implementation in an isolated subprocess and directory.
It covers initial provisioning, repeat endorsement, a nonce-bearing PCR quote
and its signature verification, shutdown/startup, collision and recovery,
clear, endorsement-seed rotation, and absence of leaked transient objects.
These tests do not exercise an AMD-signed SNP report. End-to-end validation
still requires an SNP guest and a verifier implementing the manifest contract.
