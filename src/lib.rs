#![forbid(unsafe_code)]

//! Identify by ssh-key: the fingerprint of the public key the peer presented,
//! read off the connection and not verified.
//!
//! RFC 4252 public-key authentication has the client name a key and then sign
//! the session with it. The transport that ran the exchange — SFTP, SCP, an
//! SSH tunnel — reports the key as its fingerprint, and this identifier calls
//! that the claim. The signature and the session identifier it was made over,
//! where the transport kept them, ride as proof for `authenticate/ssh-key`,
//! which is where the signature is checked. Nothing here checks it.
//!
//! The transport vocabulary this reads:
//!
//! ```text
//! ssh.key         SHA256:<base64>, as OpenSSH prints it   the claim
//! ssh.signature   the signature, base64                   proof ssh-key.signature
//! ssh.session     the session identifier, base64          proof ssh-key.session
//! ```
//!
//! Only a pushed arrival carries a passed claim. Where Xmip was the SSH
//! client, the key in play was Xmip's own and says nothing about the source.

use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
use xcore::{Arriving, Mechanism};

/// The property carrying the presented key's fingerprint.
pub const KEY: &str = "ssh.key";
/// The property carrying the signature the peer made with the key.
pub const SIGNATURE: &str = "ssh.signature";
/// The property carrying the session identifier the signature covers.
pub const SESSION: &str = "ssh.session";
/// The proof name the signature rides under.
pub const SIGNATURE_PROOF: &str = "ssh-key.signature";
/// The proof name the session identifier rides under.
pub const SESSION_PROOF: &str = "ssh-key.session";

const FINGERPRINT_PREFIX: &str = "SHA256:";

/// Reads the public key fingerprint the transport reported.
#[derive(Clone, Copy, Debug, Default)]
pub struct SshKey;

impl TransportIdentifier for SshKey {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::ssh_key()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let Some(fingerprint) = arrival.property(KEY).map(str::trim) else {
            return Ok(None);
        };
        check_fingerprint(fingerprint)?;

        let mut claim = Presented::passed(self.mechanism(), fingerprint);
        if let Some(signature) = arrival.property(SIGNATURE) {
            claim = claim.with_proof(SIGNATURE_PROOF, signature);
        }
        if let Some(session) = arrival.property(SESSION) {
            claim = claim.with_proof(SESSION_PROOF, session);
        }

        Ok(Some(claim))
    }
}

/// `SHA256:` followed by the base64 of thirty-two bytes, which is forty-three
/// characters without padding as OpenSSH prints it, or forty-four with.
fn check_fingerprint(fingerprint: &str) -> Result<(), IdentifyError> {
    let Some(digest) = fingerprint.strip_prefix(FINGERPRINT_PREFIX) else {
        return Err(IdentifyError::new(format!(
            "the SSH key fingerprint is not SHA256: `{fingerprint}`"
        )));
    };
    let body = digest.trim_end_matches('=');
    let base64 = body
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/');
    if body.len() != 43 || !base64 {
        return Err(IdentifyError::new(
            "the SSH key fingerprint is not the base64 of a SHA-256 digest",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stream::Stream;
    use xcore::{Established, Layer, StreamId};

    const FINGERPRINT: &str = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8";

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn pushed<'a>(stream: &'a Stream, properties: &'a [(String, String)]) -> StreamArrival<'a> {
        StreamArrival::new(stream, Arriving::Pushed, "sftp://xmip/in", properties)
    }

    #[test]
    fn a_presented_key_is_presented_by_its_fingerprint() {
        let stream = stream();
        let properties = [(KEY.to_string(), FINGERPRINT.to_string())];

        let claim = SshKey
            .identify(&pushed(&stream, &properties))
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, FINGERPRINT);
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(claim.mechanism.name(), "ssh-key");
        assert!(claim.proof(SIGNATURE_PROOF).is_none());
    }

    #[test]
    fn the_signature_and_session_ride_as_proof_where_the_transport_kept_them() {
        let stream = stream();
        let properties = [
            (KEY.to_string(), FINGERPRINT.to_string()),
            (SIGNATURE.to_string(), "c2ln".to_string()),
            (SESSION.to_string(), "c2Vzc2lvbg".to_string()),
        ];

        let claim = SshKey
            .identify(&pushed(&stream, &properties))
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.proof(SIGNATURE_PROOF), Some("c2ln"));
        assert_eq!(claim.proof(SESSION_PROOF), Some("c2Vzc2lvbg"));
        assert!(claim.evidence.is_empty());
    }

    #[test]
    fn an_arrival_without_a_key_presents_nothing() {
        let stream = stream();
        let properties = [("ssh.user".to_string(), "partner".to_string())];

        assert!(
            SshKey
                .identify(&pushed(&stream, &properties))
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_fingerprint_that_is_not_sha256_is_an_error_naming_why() {
        let stream = stream();
        let properties = [(
            KEY.to_string(),
            "MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48".to_string(),
        )];

        let failure = SshKey
            .identify(&pushed(&stream, &properties))
            .expect_err("not SHA256");

        assert!(failure.message.contains("not SHA256"), "{failure}");
    }

    #[test]
    fn a_fingerprint_of_the_wrong_length_is_an_error_naming_why() {
        let stream = stream();
        let properties = [(KEY.to_string(), "SHA256:nThbg6".to_string())];

        let failure = SshKey
            .identify(&pushed(&stream, &properties))
            .expect_err("too short");

        assert!(failure.message.contains("SHA-256 digest"), "{failure}");
    }

    #[test]
    fn a_scheduled_pickup_presents_nothing_because_the_key_was_xmips_own() {
        let stream = stream();
        let properties = [(KEY.to_string(), FINGERPRINT.to_string())];
        let arrival = StreamArrival::new(
            &stream,
            Arriving::Scheduled,
            "sftp://partner/out",
            &properties,
        );

        assert!(SshKey.identify(&arrival).expect("read").is_none());
    }
}
