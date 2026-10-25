// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Coconut-SVSM authors
//

use super::*;
use alloc::collections::VecDeque;
use alloc::vec;
use core::cell::RefCell;

use crate::protocols::vtpm::TpmPlatformCommand;
use crate::vtpm::VtpmProtocolInterface;

const TRANSIENT: u32 = 0x8000_0000;
const PUBLIC: &[u8] = b"generated-public-area";

struct MockTpm {
    exchanges: RefCell<VecDeque<(u32, Vec<u8>)>>,
}

impl MockTpm {
    fn new(exchanges: Vec<(u32, Vec<u8>)>) -> Self {
        Self {
            exchanges: RefCell::new(exchanges.into()),
        }
    }

    fn done(&self) {
        assert!(self.exchanges.borrow().is_empty());
    }
}

impl VtpmProtocolInterface for MockTpm {
    fn get_supported_commands(&self) -> &[TpmPlatformCommand] {
        &[]
    }
}

impl TcgTpmSimulatorInterface for MockTpm {
    fn send_tpm_command(&self, cmd: &[u8], locality: u8) -> Result<Vec<u8>, SvsmReqError> {
        assert_eq!(locality, 0);
        assert_eq!(
            u32::from_be_bytes(cmd[2..6].try_into().unwrap()) as usize,
            cmd.len()
        );
        let (code, response) = self.exchanges.borrow_mut().pop_front().unwrap();
        assert_eq!(u32::from_be_bytes(cmd[6..10].try_into().unwrap()), code);
        match code {
            TPM_CC_READ_PUBLIC => assert_eq!(&cmd[10..14], &PERSISTENT_HANDLE.to_be_bytes()),
            TPM_CC_FLUSH_CONTEXT => assert_eq!(&cmd[10..14], &TRANSIENT.to_be_bytes()),
            TPM_CC_EVICT_CONTROL => {
                assert_eq!(&cmd[10..14], &TPM_RH_OWNER.to_be_bytes());
                assert_eq!(&cmd[14..18], &TRANSIENT.to_be_bytes());
                assert_eq!(&cmd[31..35], &PERSISTENT_HANDLE.to_be_bytes());
            }
            0x131 => {
                let expected = create_endorsement_primary_cmd(&template());
                assert_eq!(cmd, &expected[..cmd.len()]);
            }
            _ => panic!("unexpected command"),
        }
        Ok(response)
    }

    fn signal_poweron(&mut self, _: bool) -> Result<(), SvsmReqError> {
        unreachable!()
    }

    fn signal_nvon(&self) -> Result<(), SvsmReqError> {
        unreachable!()
    }
}

fn response(code: u32, body: &[u8]) -> Vec<u8> {
    let mut data = vec![0x80, 0x01];
    data.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    data.extend_from_slice(&code.to_be_bytes());
    data.extend_from_slice(body);
    data
}

fn public_response(public: &[u8]) -> Vec<u8> {
    let mut body = (public.len() as u16).to_be_bytes().to_vec();
    body.extend_from_slice(public);
    response(0, &body)
}

fn primary_response() -> Vec<u8> {
    let mut body = TRANSIENT.to_be_bytes().to_vec();
    body.extend_from_slice(&((2 + PUBLIC.len()) as u32).to_be_bytes());
    body.extend_from_slice(&(PUBLIC.len() as u16).to_be_bytes());
    body.extend_from_slice(PUBLIC);
    let mut data = response(0, &body);
    data[1] = 2;
    data
}

#[test]
fn provisions_and_binds_handle_and_public() {
    let tpm = MockTpm::new(vec![
        (0x131, primary_response()),
        (TPM_CC_READ_PUBLIC, response(TPM_RC_HANDLE_1, &[])),
        (TPM_CC_EVICT_CONTROL, response(0, &[])),
        (TPM_CC_READ_PUBLIC, public_response(PUBLIC)),
        (TPM_CC_FLUSH_CONTEXT, response(0, &[])),
    ]);
    let manifest = manifest(&tpm).unwrap();
    assert_eq!(&manifest[..4], &PERSISTENT_HANDLE.to_le_bytes());
    assert_eq!(&manifest[4..], PUBLIC);
    tpm.done();
}

#[test]
fn revalidates_existing_key_without_nv_write() {
    let tpm = MockTpm::new(vec![
        (0x131, primary_response()),
        (TPM_CC_READ_PUBLIC, public_response(PUBLIC)),
        (TPM_CC_FLUSH_CONTEXT, response(0, &[])),
    ]);
    assert!(manifest(&tpm).is_ok());
    tpm.done();
}

#[test]
fn rejects_collision_without_evicting_guest_key() {
    let tpm = MockTpm::new(vec![
        (0x131, primary_response()),
        (TPM_CC_READ_PUBLIC, public_response(b"guest-key")),
        (TPM_CC_FLUSH_CONTEXT, response(0, &[])),
    ]);
    assert!(manifest(&tpm).is_err());
    tpm.done();
}

#[test]
fn propagates_tpm_errors_and_always_flushes() {
    for code in [0x922, 0x14a, 0x101] {
        let tpm = MockTpm::new(vec![
            (0x131, primary_response()),
            (TPM_CC_READ_PUBLIC, response(code, &[])),
            (TPM_CC_FLUSH_CONTEXT, response(0, &[])),
        ]);
        assert!(matches!(manifest(&tpm), Err(SvsmVTpmError::CommandError(rc)) if rc == code));
        tpm.done();
    }
    let tpm = MockTpm::new(vec![
        (0x131, primary_response()),
        (TPM_CC_READ_PUBLIC, response(TPM_RC_HANDLE_1, &[])),
        (TPM_CC_EVICT_CONTROL, response(0x9a2, &[])),
        (TPM_CC_FLUSH_CONTEXT, response(0, &[])),
    ]);
    assert!(matches!(
        manifest(&tpm),
        Err(SvsmVTpmError::CommandError(0x9a2))
    ));
    tpm.done();
}

#[test]
fn rejects_failed_readback_and_cleanup() {
    let tpm = MockTpm::new(vec![
        (0x131, primary_response()),
        (TPM_CC_READ_PUBLIC, response(TPM_RC_HANDLE_1, &[])),
        (TPM_CC_EVICT_CONTROL, response(0, &[])),
        (TPM_CC_READ_PUBLIC, public_response(b"wrong-key")),
        (TPM_CC_FLUSH_CONTEXT, response(0, &[])),
    ]);
    assert!(manifest(&tpm).is_err());
    tpm.done();

    let tpm = MockTpm::new(vec![
        (0x131, primary_response()),
        (TPM_CC_READ_PUBLIC, public_response(PUBLIC)),
        (TPM_CC_FLUSH_CONTEXT, response(0x101, &[])),
    ]);
    assert!(matches!(
        manifest(&tpm),
        Err(SvsmVTpmError::CommandError(0x101))
    ));
    tpm.done();
}

#[test]
fn rejects_malformed_public_and_flushes_primary() {
    let mut malformed = primary_response();
    malformed[18..20].copy_from_slice(&u16::MAX.to_be_bytes());
    let tpm = MockTpm::new(vec![
        (0x131, malformed),
        (TPM_CC_FLUSH_CONTEXT, response(0, &[])),
    ]);
    assert!(manifest(&tpm).is_err());
    tpm.done();

    for body in [&[][..], &[0][..], &[0, 10, 1][..], &[0, 0][..]] {
        assert!(tpm2b(body, 0).is_err());
    }
}

#[test]
fn validates_command_and_response_lengths() {
    let tpm = MockTpm::new(vec![]);
    assert!(checked_send(&tpm, &mut [0; 9], true).is_err());
    let mut cmd = command(TPM_CC_READ_PUBLIC, &[PERSISTENT_HANDLE], false);
    cmd[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(checked_send(&tpm, &mut cmd, false).is_err());
    tpm.done();

    let mut wrong_size = response(0, &[]);
    wrong_size[5] = 11;
    for malformed in [vec![0; 9], wrong_size] {
        let tpm = MockTpm::new(vec![(TPM_CC_READ_PUBLIC, malformed)]);
        assert!(read_public(&tpm, PERSISTENT_HANDLE).is_err());
        tpm.done();
    }
}

#[cfg(all(not(target_os = "none"), not(miri)))]
mod simulator {
    extern crate std;

    use super::*;
    use crate::vtpm::{VtpmInterface, tcgtpm::TcgTpm};
    use std::{env, fs, process};

    fn send(tpm: &TcgTpm, code: u32, handles: &[u32], auth: bool, params: &[u8]) -> Vec<u8> {
        let mut cmd = command(code, handles, auth);
        cmd.extend_from_slice(params);
        // The reference TPM requests a retry when first persisting DA-use state.
        for _ in 0..3 {
            match checked_send(tpm, &mut cmd, true) {
                Ok(response) => return response,
                Err(SvsmVTpmError::CommandError(0x922)) => {}
                Err(err) => panic!("TPM command {code:#x} failed: {err:?}"),
            }
        }
        panic!("TPM command {code:#x} kept requesting a retry");
    }

    fn evict(tpm: &TcgTpm, object: u32, persistent: u32) {
        send(
            tpm,
            TPM_CC_EVICT_CONTROL,
            &[TPM_RH_OWNER, object],
            true,
            &persistent.to_be_bytes(),
        );
    }

    fn assert_no_transient_objects(tpm: &TcgTpm) {
        let mut params = 1u32.to_be_bytes().to_vec(); // TPM_CAP_HANDLES
        params.extend_from_slice(&TRANSIENT.to_be_bytes());
        params.extend_from_slice(&64u32.to_be_bytes());
        let response = send(tpm, 0x17a, &[], false, &params);
        assert_eq!(&response[15..19], &[0; 4]);
    }

    #[test]
    fn lifecycle() {
        // The reference TPM has process-global state and opens a relative NVChip.
        // Run it in a child with its own working directory, not in parallel tests.
        const CHILD: &str = "SVSM_MANAGED_AK_TEST_CHILD";
        if env::var_os(CHILD).is_none() {
            let dir = env::temp_dir().join(std::format!("svsm-ak-{}", process::id()));
            fs::create_dir(&dir).unwrap();
            let output = process::Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vtpm::tcgtpm::ak::tests::simulator::lifecycle",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .current_dir(&dir)
                .output()
                .unwrap();
            let nv = dir.join("NVChip");
            if nv.exists() {
                fs::remove_file(nv).unwrap();
            }
            fs::remove_dir(dir).unwrap();
            assert!(
                output.status.success(),
                "simulator failed:\n{}\n{}",
                std::string::String::from_utf8_lossy(&output.stdout),
                std::string::String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let mut tpm = TcgTpm::new();
        tpm.init().unwrap();
        assert!(manifest(&tpm).is_err()); // Firmware still owns TPM2_Startup.
        send(&tpm, 0x144, &[], false, &[0, 0]);
        send(&tpm, 0x143, &[], false, &[1]); // Full self-test.

        let first = manifest(&tpm).unwrap();
        assert_eq!(&first[..4], &PERSISTENT_HANDLE.to_le_bytes());
        assert_eq!(&first[4..], read_public(&tpm, PERSISTENT_HANDLE).unwrap());
        let public = &first[4..];
        assert_eq!(&public[..8], &[0, 1, 0, 0x0b, 0, 5, 0, 0x72]);
        for _ in 0..5 {
            assert_eq!(manifest(&tpm).unwrap(), first);
            assert_no_transient_objects(&tpm);
        }

        // Quote a real PCR with a nonce, and verify the signature in the TPM.
        let nonce = b"fresh verifier challenge";
        let mut params = (nonce.len() as u16).to_be_bytes().to_vec();
        params.extend_from_slice(nonce);
        params.extend_from_slice(&[0, 0x10]); // TPM_ALG_NULL: use AK default scheme.
        params.extend_from_slice(&[0, 0, 0, 1, 0, 0x0b, 3, 1, 0, 0]); // SHA256 PCR 0
        let quote_response = send(&tpm, 0x158, &[PERSISTENT_HANDLE], true, &params);
        let quote = tpm2b(&quote_response, 14).unwrap();
        assert_eq!(&quote[..6], &[0xff, 0x54, 0x43, 0x47, 0x80, 0x18]);
        let signer = tpm2b(quote, 6).unwrap();
        assert_eq!(tpm2b(quote, 8 + signer.len()).unwrap(), nonce);
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(quote);
        let signature = &quote_response[16 + quote.len()..];
        let signature_len = 6 + usize::from(u16::from_be_bytes([signature[4], signature[5]]));
        let mut verify = 32u16.to_be_bytes().to_vec();
        verify.extend_from_slice(digest.as_slice());
        verify.extend_from_slice(&signature[..signature_len]);
        send(&tpm, 0x177, &[PERSISTENT_HANDLE], false, &verify);
        verify[2] ^= 1;
        let mut bad_verify = command(0x177, &[PERSISTENT_HANDLE], false);
        bad_verify.extend_from_slice(&verify);
        assert!(checked_send(&tpm, &mut bad_verify, true).is_err());

        // A normal TPM shutdown/startup preserves the persistent AK.
        send(&tpm, 0x145, &[], false, &[0, 0]);
        tpm.signal_poweron(true).unwrap();
        tpm.signal_nvon().unwrap();
        send(&tpm, 0x144, &[], false, &[0, 0]);
        assert_eq!(manifest(&tpm).unwrap(), first);

        // Never overwrite an unrelated guest key at the selected handle.
        evict(&tpm, PERSISTENT_HANDLE, PERSISTENT_HANDLE);
        let mut other_template = template();
        *other_template.last_mut().unwrap() ^= 1;
        let mut cmd = create_endorsement_primary_cmd(&other_template);
        let other = checked_send(&tpm, &mut cmd, false).unwrap();
        let other_handle = u32::from_be_bytes(other[10..14].try_into().unwrap());
        let guest_handle = PERSISTENT_HANDLE + 1;
        evict(&tpm, other_handle, guest_handle);
        evict(&tpm, other_handle, PERSISTENT_HANDLE);
        flush(&tpm, other_handle).unwrap();
        let guest_public = read_public(&tpm, PERSISTENT_HANDLE).unwrap();
        assert!(manifest(&tpm).is_err());
        assert_eq!(read_public(&tpm, PERSISTENT_HANDLE).unwrap(), guest_public);
        assert_no_transient_objects(&tpm);
        evict(&tpm, PERSISTENT_HANDLE, PERSISTENT_HANDLE);
        assert_eq!(manifest(&tpm).unwrap(), first);
        assert_eq!(read_public(&tpm, guest_handle).unwrap(), guest_public);

        // Guest hierarchy administration can deny service, without leaking objects.
        evict(&tpm, PERSISTENT_HANDLE, PERSISTENT_HANDLE);
        send(&tpm, 0x129, &[TPM_RH_OWNER], true, &[0, 1, b'x']);
        assert!(manifest(&tpm).is_err());
        assert_no_transient_objects(&tpm);

        // Clear resets authorizations and objects, but preserves the endorsement seed.
        send(&tpm, 0x126, &[0x4000_000c], true, &[]);
        assert_eq!(manifest(&tpm).unwrap(), first);
        send(&tpm, 0x129, &[0x4000_000b], true, &[0, 1, b'x']);
        assert!(manifest(&tpm).is_err());
        assert_no_transient_objects(&tpm);
        send(&tpm, 0x126, &[0x4000_000c], true, &[]);
        assert_eq!(manifest(&tpm).unwrap(), first);
        // ChangeEPS rotates the endorsement seed: no stale AK cache is trusted.
        send(&tpm, 0x124, &[0x4000_000c], true, &[]);
        let after_change_eps = manifest(&tpm).unwrap();
        assert_ne!(after_change_eps, first);
        assert_no_transient_objects(&tpm);

        // The existing EK service remains independently usable alongside the AK.
        let ek = tpm.get_ekpub().unwrap();
        assert_ne!(&after_change_eps[4..], ek);
        assert_eq!(manifest(&tpm).unwrap(), after_change_eps);
        assert_eq!(tpm.get_ekpub().unwrap(), ek);
    }
}
