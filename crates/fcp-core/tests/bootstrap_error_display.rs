use std::time::Duration;

use fcp_bootstrap::{BootstrapError, CertificateSelectionRefusal};

struct BootstrapErrorDisplayCase {
    variant: &'static str,
    error: BootstrapError,
    expected: &'static str,
    remediation_hint: &'static str,
}

const BOOTSTRAP_ERROR_VARIANT_COUNT: usize = 28;

#[allow(clippy::too_many_lines)]
fn display_cases() -> Vec<BootstrapErrorDisplayCase> {
    vec![
        BootstrapErrorDisplayCase {
            variant: "TimeSkew",
            error: BootstrapError::TimeSkew {
                drift: Duration::from_secs(120),
                suggestion: "sync system clock",
            },
            expected: "time skew detected: drift=120s, suggestion: sync system clock",
            remediation_hint: "sync system clock",
        },
        BootstrapErrorDisplayCase {
            variant: "AlreadyExists",
            error: BootstrapError::AlreadyExists {
                fingerprint: "blake3:abc123".into(),
            },
            expected: "genesis already exists: fingerprint=blake3:abc123; remediation: resume the existing bootstrap or choose an empty data directory",
            remediation_hint: "resume the existing bootstrap",
        },
        BootstrapErrorDisplayCase {
            variant: "BootstrapInProgress",
            error: BootstrapError::BootstrapInProgress {
                data_dir: "mesh-data".into(),
            },
            expected: "bootstrap already in progress in mesh-data; remediation: wait for the active workflow to finish before retrying; force overwrite cannot bypass the bootstrap lease",
            remediation_hint: "wait for the active workflow to finish",
        },
        BootstrapErrorDisplayCase {
            variant: "PartialState",
            error: BootstrapError::PartialState {
                phase: "owner-keygen".into(),
            },
            expected: "partial bootstrap state detected at phase: owner-keygen; remediation: resume bootstrap from the recorded phase or clean the partial state before restarting",
            remediation_hint: "resume bootstrap from the recorded phase",
        },
        BootstrapErrorDisplayCase {
            variant: "NotInitialized",
            error: BootstrapError::NotInitialized,
            expected: "no partial bootstrap state to resume: data directory is fresh; remediation: use BootstrapWorkflow::new to start bootstrap",
            remediation_hint: "use BootstrapWorkflow::new",
        },
        BootstrapErrorDisplayCase {
            variant: "InvalidRecoveryPhrase",
            error: BootstrapError::InvalidRecoveryPhrase("bad checksum".into()),
            expected: "invalid recovery phrase: bad checksum; remediation: re-enter the recovery phrase exactly as issued",
            remediation_hint: "re-enter the recovery phrase",
        },
        BootstrapErrorDisplayCase {
            variant: "FingerprintMismatch",
            error: BootstrapError::FingerprintMismatch {
                expected: "expected-fingerprint".into(),
                actual: "actual-fingerprint".into(),
            },
            expected: "genesis fingerprint mismatch: expected=expected-fingerprint, actual=actual-fingerprint; remediation: verify the recovery phrase and target genesis fingerprint before retrying",
            remediation_hint: "verify the recovery phrase",
        },
        BootstrapErrorDisplayCase {
            variant: "Ceremony",
            error: BootstrapError::Ceremony("round failed".into()),
            expected: "ceremony error: round failed; remediation: inspect ceremony logs and retry after correcting the participant failure",
            remediation_hint: "inspect ceremony logs",
        },
        BootstrapErrorDisplayCase {
            variant: "CeremonyTimeout",
            error: BootstrapError::CeremonyTimeout {
                phase: "round-two".into(),
            },
            expected: "ceremony timed out at phase: round-two; remediation: ensure all participants are online and retry the ceremony",
            remediation_hint: "ensure all participants are online",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareToken",
            error: BootstrapError::HardwareToken("PKCS#11 init failed".into()),
            expected: "hardware token error: PKCS#11 init failed; remediation: check token provider, slot, and PIN configuration",
            remediation_hint: "check token provider",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenKeyNotFound",
            error: BootstrapError::HardwareTokenKeyNotFound {
                key: "owner-key".into(),
            },
            expected: "hardware token key not found: owner-key - ensure the token is provisioned with the expected key label",
            remediation_hint: "ensure the token is provisioned",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenCertificateSelectionFailed",
            error: BootstrapError::HardwareTokenCertificateSelectionFailed {
                refusal: CertificateSelectionRefusal::NoCertificates,
            },
            expected: "hardware token certificate selection failed: no certificates found on token; remediation: provision a token certificate/key pair that matches FCP owner-signing requirements",
            remediation_hint: "provision a token certificate/key pair",
        },
        BootstrapErrorDisplayCase {
            variant: "NoHardwareTokens",
            error: BootstrapError::NoHardwareTokens,
            expected: "no hardware tokens detected; remediation: connect a supported hardware token or configure provider library paths",
            remediation_hint: "connect a supported hardware token",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenPinRequired",
            error: BootstrapError::HardwareTokenPinRequired,
            expected: "hardware token PIN is required: provide via --hardware-token-pin or interactive prompt",
            remediation_hint: "provide via --hardware-token-pin",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenInvalidPin",
            error: BootstrapError::HardwareTokenInvalidPin,
            expected: "hardware token PIN was rejected: verify and retry; repeated failures will lock the token",
            remediation_hint: "verify and retry",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenPinLocked",
            error: BootstrapError::HardwareTokenPinLocked,
            expected: "hardware token PIN is locked: use the token vendor's management tool to reset it",
            remediation_hint: "use the token vendor's management tool",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenNotFound",
            error: BootstrapError::HardwareTokenNotFound {
                locator: "YubiKey slot 0".into(),
            },
            expected: "hardware token not found: YubiKey slot 0 - verify token is connected and provider library is installed",
            remediation_hint: "verify token is connected",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenUnsupported",
            error: BootstrapError::HardwareTokenUnsupported {
                mechanism: "RSA-PKCS".into(),
            },
            expected: "hardware token does not support RSA-PKCS: Ed25519 or EdDSA signing is required",
            remediation_hint: "Ed25519 or EdDSA signing is required",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenDisconnected",
            error: BootstrapError::HardwareTokenDisconnected,
            expected: "hardware token disconnected: re-insert the token and retry",
            remediation_hint: "re-insert the token",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenSessionExpired",
            error: BootstrapError::HardwareTokenSessionExpired {
                elapsed: Duration::from_secs(301),
                timeout: Duration::from_secs(300),
            },
            expected: "hardware token session expired after 301s (timeout: 300s): retry or increase --session-timeout",
            remediation_hint: "increase --session-timeout",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenCancelled",
            error: BootstrapError::HardwareTokenCancelled,
            expected: "hardware token operation was cancelled: retry when ready",
            remediation_hint: "retry when ready",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenProviderFault",
            error: BootstrapError::HardwareTokenProviderFault {
                detail: "CKR_DEVICE_ERROR".into(),
            },
            expected: "hardware token provider fault: CKR_DEVICE_ERROR - check provider library and token firmware",
            remediation_hint: "check provider library",
        },
        BootstrapErrorDisplayCase {
            variant: "HardwareTokenEnrollmentNotImplemented",
            error: BootstrapError::HardwareTokenEnrollmentNotImplemented {
                token_display: "YubiKey 5".into(),
                key_material: "Ed25519".into(),
            },
            expected: "hardware token provisioning enrollment is not implemented yet for token YubiKey 5 using Ed25519; remediation: use a supported bootstrap enrollment path before retrying",
            remediation_hint: "use a supported bootstrap enrollment path",
        },
        BootstrapErrorDisplayCase {
            variant: "Crypto",
            error: BootstrapError::Crypto("key derivation failed".into()),
            expected: "cryptographic error: key derivation failed; remediation: verify key material and retry with a fresh bootstrap context",
            remediation_hint: "verify key material",
        },
        BootstrapErrorDisplayCase {
            variant: "Io",
            error: BootstrapError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "data dir denied",
            )),
            expected: "IO error: data dir denied; remediation: check filesystem permissions and available disk space",
            remediation_hint: "check filesystem permissions",
        },
        BootstrapErrorDisplayCase {
            variant: "Serialization",
            error: BootstrapError::Serialization("CBOR decode failed".into()),
            expected: "serialization error: CBOR decode failed; remediation: discard corrupted bootstrap artifacts and retry from a known-good state",
            remediation_hint: "discard corrupted bootstrap artifacts",
        },
        BootstrapErrorDisplayCase {
            variant: "Config",
            error: BootstrapError::Config("data_dir required".into()),
            expected: "configuration error: data_dir required; remediation: correct bootstrap configuration before retrying",
            remediation_hint: "correct bootstrap configuration",
        },
        BootstrapErrorDisplayCase {
            variant: "Internal",
            error: BootstrapError::Internal("unexpected state".into()),
            expected: "internal error: unexpected state; remediation: report this bug with bootstrap logs",
            remediation_hint: "report this bug",
        },
    ]
}

#[test]
fn bootstrap_error_display_is_pinned_for_each_variant_with_remediation() {
    let cases = display_cases();
    assert_eq!(cases.len(), BOOTSTRAP_ERROR_VARIANT_COUNT);

    for case in cases {
        let rendered = case.error.to_string();

        assert_eq!(rendered, case.expected, "{}", case.variant);
        assert!(
            rendered.contains(case.remediation_hint),
            "{} display omitted remediation hint: {rendered}",
            case.variant
        );
    }
}
