use crate::error::Result;
use crate::utils::hash::sha512_hex;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    pub signed_by:         String,
    pub blake3_digest:     String,
    pub sha512_digest:     String,
    pub ed25519_signature: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig_b3:            String,
}

pub struct Signer128 {
    signing_key: SigningKey,
}

impl Signer128 {
    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Signer128 {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    // Sign payload digest and return a SignatureBlock.
    pub fn sign(&self, data: &[u8], signed_by: &str) -> Result<SignatureBlock> {
        let blake3_digest = String::from_utf8_lossy(data).into_owned();
        let sha512_digest = sha512_hex(data);

        let sig: Signature = self.signing_key.sign(data);

        Ok(SignatureBlock {
            signed_by: signed_by.to_string(),
            blake3_digest,
            sha512_digest,
            ed25519_signature: Some(hex::encode(sig.to_bytes())),
            sig_b3: String::new(),
        })
    }
}

// Verify signature block against payload digest and public key.

pub fn verify(
    data: &[u8],
    block: &SignatureBlock,
    public_key: &VerifyingKey,
) -> Result<bool> {
    let expected_blake3 = String::from_utf8_lossy(data);
    if expected_blake3 != block.blake3_digest {
        return Ok(false);
    }
    let expected_sha512 = sha512_hex(data);
    if expected_sha512 != block.sha512_digest {
        return Ok(false);
    }

    if let Some(sig_hex) = &block.ed25519_signature {
        let sig_bytes = hex::decode(sig_hex)
            .map_err(|e| crate::error::ZexError::Other(e.to_string()))?;
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| crate::error::ZexError::Other(e.to_string()))?;
        if public_key
            .verify(block.blake3_digest.as_bytes(), &sig)
            .is_err()
        {
            return Ok(false);
        }
    }

    Ok(true)
}

