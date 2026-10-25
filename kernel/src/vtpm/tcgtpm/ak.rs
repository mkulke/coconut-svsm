// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Coconut-SVSM authors
//

//! Optional, directly endorsed attestation key. Callers must hold the vTPM lock.

extern crate alloc;

use alloc::vec::Vec;

use crate::protocols::errors::SvsmReqError;
use crate::vtpm::{SvsmVTpmError, TcgTpmSimulatorInterface};

use super::tss::{checked_send, create_endorsement_primary_cmd, extend_empty_auth};

/// Experimental owner-range persistent handle reserved when `vtpm-ak` is enabled.
pub const PERSISTENT_HANDLE: u32 = 0x8101_0002;

const TPM_RH_OWNER: u32 = 0x4000_0001;
const TPM_CC_EVICT_CONTROL: u32 = 0x0000_0120;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const TPM_CC_READ_PUBLIC: u32 = 0x0000_0173;
const TPM_RC_HANDLE_1: u32 = 0x0000_018b;

fn template() -> Vec<u8> {
    let mut public = Vec::from([
        0x00, 0x01, // TPM_ALG_RSA
        0x00, 0x0b, // nameAlg: TPM_ALG_SHA256
        0x00, 0x05, 0x00, 0x72, // fixedTPM, fixedParent, sensitiveDataOrigin,
        // userWithAuth, restricted, sign
        0x00, 0x00, // empty authPolicy
        0x00, 0x10, // symmetric: TPM_ALG_NULL
        0x00, 0x14, 0x00, 0x0b, // scheme: RSASSA with SHA-256
        0x08, 0x00, // RSA 2048
        0x00, 0x00, 0x00, 0x00, // default exponent
    ]);
    // Domain-separate this primary from keys created with a generic AK template.
    let unique = b"Coconut-SVSM managed AK v1";
    public.extend_from_slice(&(unique.len() as u16).to_be_bytes());
    public.extend_from_slice(unique);
    public
}

fn command(code: u32, handles: &[u32], authorized: bool) -> Vec<u8> {
    let mut cmd = Vec::new();
    let tag = if authorized { 0x8002u16 } else { 0x8001u16 };
    cmd.extend_from_slice(&tag.to_be_bytes());
    cmd.extend_from_slice(&[0; 4]);
    cmd.extend_from_slice(&code.to_be_bytes());
    for handle in handles {
        cmd.extend_from_slice(&handle.to_be_bytes());
    }
    if authorized {
        extend_empty_auth(&mut cmd);
    }
    cmd
}

fn tpm2b(data: &[u8], offset: usize) -> Result<&[u8], SvsmVTpmError> {
    let size = data
        .get(offset..offset + 2)
        .ok_or_else(SvsmReqError::invalid_request)?;
    let size = usize::from(u16::from_be_bytes([size[0], size[1]]));
    data.get(offset + 2..offset + 2 + size)
        .filter(|public| !public.is_empty())
        .ok_or_else(|| SvsmReqError::invalid_request().into())
}

fn read_public<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    handle: u32,
) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = command(TPM_CC_READ_PUBLIC, &[handle], false);
    let response = checked_send(vtpm, &mut cmd, true)?;
    Ok(tpm2b(&response, 10)?.to_vec())
}

fn flush<T: TcgTpmSimulatorInterface>(vtpm: &T, handle: u32) -> Result<(), SvsmVTpmError> {
    let mut cmd = command(TPM_CC_FLUSH_CONTEXT, &[handle], false);
    checked_send(vtpm, &mut cmd, true)?;
    Ok(())
}

fn ensure_persistent<T: TcgTpmSimulatorInterface>(
    vtpm: &T,
    transient: u32,
    expected: &[u8],
) -> Result<(), SvsmVTpmError> {
    match read_public(vtpm, PERSISTENT_HANDLE) {
        Ok(public) => {
            if public != expected {
                log::error!("VTPM: managed AK persistent handle is occupied by another key");
                return Err(SvsmReqError::invalid_request().into());
            }
            return Ok(());
        }
        Err(SvsmVTpmError::CommandError(TPM_RC_HANDLE_1)) => {}
        Err(err) => return Err(err),
    }

    let mut cmd = command(TPM_CC_EVICT_CONTROL, &[TPM_RH_OWNER, transient], true);
    cmd.extend_from_slice(&PERSISTENT_HANDLE.to_be_bytes());
    checked_send(vtpm, &mut cmd, true)?;
    if read_public(vtpm, PERSISTENT_HANDLE)? != expected {
        log::error!("VTPM: persisted managed AK does not match the generated key");
        return Err(SvsmReqError::invalid_request().into());
    }
    Ok(())
}

/// Return `persistent_handle_le || TPMT_PUBLIC`, creating the AK if absent.
///
/// Recreate the endorsement primary on every request: neither a cached public
/// key nor an object at a guest-controlled persistent handle proves provenance.
/// The guest retains control of hierarchy authorization and can deny service.
pub fn manifest<T: TcgTpmSimulatorInterface>(vtpm: &T) -> Result<Vec<u8>, SvsmVTpmError> {
    let mut cmd = create_endorsement_primary_cmd(&template());
    let response = checked_send(vtpm, &mut cmd, false)?;
    let handle_bytes = response
        .get(10..14)
        .ok_or_else(SvsmReqError::invalid_request)?;
    let handle = u32::from_be_bytes(handle_bytes.try_into().unwrap());

    let result = (|| {
        let parameter_size = response
            .get(14..18)
            .ok_or_else(SvsmReqError::invalid_request)?;
        let parameter_size = u32::from_be_bytes(parameter_size.try_into().unwrap()) as usize;
        let parameters = response
            .get(18..)
            .and_then(|data| data.get(..parameter_size))
            .ok_or_else(SvsmReqError::invalid_request)?;
        let public = tpm2b(parameters, 0)?;
        ensure_persistent(vtpm, handle, public)?;

        let mut manifest = PERSISTENT_HANDLE.to_le_bytes().to_vec();
        manifest.extend_from_slice(public);
        Ok(manifest)
    })();

    if let Err(err) = flush(vtpm, handle) {
        log::error!("VTPM: failed to flush temporary managed AK: {err:?}");
        // Preserve the provisioning error if both provisioning and cleanup fail.
        return result.and(Err(err));
    }
    result
}

#[cfg(test)]
mod tests;
