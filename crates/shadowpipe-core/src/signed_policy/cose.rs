use std::convert::TryInto;

use minicbor::{Decoder, Encoder};
use ring::signature::{UnparsedPublicKey, ED25519};

use super::error::{PolicyError, Result};
use super::schema::{Ed25519PublicKey, Kid, MAX_SIGN1_BYTES};

const COSE_SIGN1_TAG: u8 = 0xd2;
const COSE_EDDSA: i64 = -8;
const PRIVATE_SCHEMA_LABEL: u64 = 1001;
const PRIVATE_SCHEMA_VERSION: u64 = 1;
const SIGNATURE_LEN: usize = 64;

const KEYSET_CONTENT_TYPE: &str = "application/shadowpipe-keyset+cbor;v=1";
const POLICY_CONTENT_TYPE: &str = "application/shadowpipe-endpoint-policy+cbor;v=2";
const LEGACY_POLICY_CONTENT_TYPE_V1: &str = "application/shadowpipe-endpoint-policy+cbor;v=1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentType {
    Keyset,
    EndpointPolicy,
}

impl ContentType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Keyset => KEYSET_CONTENT_TYPE,
            Self::EndpointPolicy => POLICY_CONTENT_TYPE,
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            KEYSET_CONTENT_TYPE => Ok(Self::Keyset),
            POLICY_CONTENT_TYPE => Ok(Self::EndpointPolicy),
            LEGACY_POLICY_CONTENT_TYPE_V1 => Err(PolicyError::invalid(
                "unsupported endpoint-policy schema 1; only schema 2 is accepted",
            )),
            _ => Err(PolicyError::invalid(format!(
                "unsupported COSE content type {value:?}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedHeader {
    pub content_type: ContentType,
    pub kid: Kid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParsedSign1 {
    pub protected: Vec<u8>,
    pub header: ProtectedHeader,
    pub payload: Vec<u8>,
    pub signature: [u8; SIGNATURE_LEN],
}

fn enc<T, E: std::fmt::Display>(value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(PolicyError::decode)
}

fn dec<T>(value: std::result::Result<T, minicbor::decode::Error>) -> Result<T> {
    value.map_err(PolicyError::decode)
}

fn finish(decoder: &Decoder<'_>, input: &[u8], what: &'static str) -> Result<()> {
    if decoder.position() != input.len() {
        return Err(PolicyError::invalid(format!(
            "{what} has {} trailing bytes",
            input.len() - decoder.position()
        )));
    }
    Ok(())
}

pub fn encode_protected_header(header: &ProtectedHeader) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new());
    enc(encoder.map(5))?;
    enc(encoder.u8(1))?;
    enc(encoder.i8(COSE_EDDSA as i8))?;
    enc(encoder.u8(2))?;
    enc(encoder.array(1))?;
    enc(encoder.u16(PRIVATE_SCHEMA_LABEL as u16))?;
    enc(encoder.u8(3))?;
    enc(encoder.str(header.content_type.as_str()))?;
    enc(encoder.u8(4))?;
    enc(encoder.bytes(header.kid.as_bytes()))?;
    enc(encoder.u16(PRIVATE_SCHEMA_LABEL as u16))?;
    enc(encoder.u8(PRIVATE_SCHEMA_VERSION as u8))?;
    Ok(encoder.into_writer())
}

fn decode_protected_header(input: &[u8]) -> Result<ProtectedHeader> {
    let mut decoder = Decoder::new(input);
    let fields = dec(decoder.map())?.ok_or_else(|| {
        PolicyError::invalid("COSE protected header uses an indefinite-length map")
    })?;
    if fields != 5 {
        return Err(PolicyError::invalid(format!(
            "COSE protected header has {fields} fields; expected 5"
        )));
    }

    let label = dec(decoder.u64())?;
    if label != 1 {
        return Err(PolicyError::invalid(format!(
            "COSE protected header expected alg label 1, found {label}"
        )));
    }
    let alg = dec(decoder.i64())?;
    if alg != COSE_EDDSA {
        return Err(PolicyError::invalid(format!(
            "COSE alg is {alg}; only EdDSA (-8) is permitted"
        )));
    }

    let label = dec(decoder.u64())?;
    if label != 2 {
        return Err(PolicyError::invalid(format!(
            "COSE protected header expected crit label 2, found {label}"
        )));
    }
    let crit_len = dec(decoder.array())?
        .ok_or_else(|| PolicyError::invalid("COSE crit uses an indefinite-length array"))?;
    if crit_len != 1 {
        return Err(PolicyError::invalid(format!(
            "COSE crit has {crit_len} entries; expected exactly one"
        )));
    }
    let critical_label = dec(decoder.u64())?;
    if critical_label != PRIVATE_SCHEMA_LABEL {
        return Err(PolicyError::invalid(format!(
            "COSE crit contains unsupported label {critical_label}"
        )));
    }

    let label = dec(decoder.u64())?;
    if label != 3 {
        return Err(PolicyError::invalid(format!(
            "COSE protected header expected content-type label 3, found {label}"
        )));
    }
    let content_type = ContentType::from_str(dec(decoder.str())?)?;

    let label = dec(decoder.u64())?;
    if label != 4 {
        return Err(PolicyError::invalid(format!(
            "COSE protected header expected kid label 4, found {label}"
        )));
    }
    let kid_bytes = dec(decoder.bytes())?;
    let kid = Kid(kid_bytes.try_into().map_err(|_| {
        PolicyError::invalid(format!(
            "COSE kid is {} bytes; expected exactly {}",
            kid_bytes.len(),
            Kid::LEN
        ))
    })?);

    let label = dec(decoder.u64())?;
    if label != PRIVATE_SCHEMA_LABEL {
        return Err(PolicyError::invalid(format!(
            "COSE protected header expected private schema label {PRIVATE_SCHEMA_LABEL}, found {label}"
        )));
    }
    let schema = dec(decoder.u64())?;
    if schema != PRIVATE_SCHEMA_VERSION {
        return Err(PolicyError::invalid(format!(
            "unsupported COSE protected-header schema {schema}"
        )));
    }
    finish(&decoder, input, "COSE protected header")?;

    let header = ProtectedHeader { content_type, kid };
    if input != encode_protected_header(&header)? {
        return Err(PolicyError::NonCanonical("COSE protected header"));
    }
    Ok(header)
}

pub fn signature_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    let parts_len = protected
        .len()
        .checked_add(payload.len())
        .ok_or_else(|| PolicyError::invalid("COSE signature input length overflow"))?;
    if parts_len > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "COSE signature input",
            actual: parts_len,
            maximum: MAX_SIGN1_BYTES,
        });
    }
    let mut encoder = Encoder::new(Vec::new());
    enc(encoder.array(4))?;
    enc(encoder.str("Signature1"))?;
    enc(encoder.bytes(protected))?;
    enc(encoder.bytes(&[]))?;
    enc(encoder.bytes(payload))?;
    Ok(encoder.into_writer())
}

pub fn encode_sign1(
    protected: &[u8],
    payload: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<Vec<u8>> {
    let parts_len = protected
        .len()
        .checked_add(payload.len())
        .ok_or_else(|| PolicyError::invalid("COSE_Sign1 input length overflow"))?;
    if parts_len > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "COSE_Sign1 input",
            actual: parts_len,
            maximum: MAX_SIGN1_BYTES,
        });
    }
    decode_protected_header(protected)?;
    let mut output = Vec::with_capacity(1 + protected.len() + payload.len() + 80);
    output.push(COSE_SIGN1_TAG);
    let mut encoder = Encoder::new(output);
    enc(encoder.array(4))?;
    enc(encoder.bytes(protected))?;
    enc(encoder.map(0))?;
    enc(encoder.bytes(payload))?;
    enc(encoder.bytes(signature))?;
    let output = encoder.into_writer();
    if output.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "COSE_Sign1",
            actual: output.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    Ok(output)
}

pub(crate) fn inspect_sign1(input: &[u8]) -> Result<ParsedSign1> {
    if input.len() > MAX_SIGN1_BYTES {
        return Err(PolicyError::TooLarge {
            what: "COSE_Sign1",
            actual: input.len(),
            maximum: MAX_SIGN1_BYTES,
        });
    }
    if input.first() != Some(&COSE_SIGN1_TAG) {
        return Err(PolicyError::invalid(
            "COSE_Sign1 must carry the canonical CBOR tag 18",
        ));
    }
    let body = &input[1..];
    let mut decoder = Decoder::new(body);
    let fields = dec(decoder.array())?
        .ok_or_else(|| PolicyError::invalid("COSE_Sign1 uses an indefinite-length array"))?;
    if fields != 4 {
        return Err(PolicyError::invalid(format!(
            "COSE_Sign1 has {fields} fields; expected 4"
        )));
    }

    let protected = dec(decoder.bytes())?.to_vec();
    let header = decode_protected_header(&protected)?;
    let unprotected = dec(decoder.map())?.ok_or_else(|| {
        PolicyError::invalid("COSE unprotected header uses an indefinite-length map")
    })?;
    if unprotected != 0 {
        return Err(PolicyError::invalid(
            "COSE unprotected header must be empty",
        ));
    }
    let payload = dec(decoder.bytes())?.to_vec();
    let raw_signature = dec(decoder.bytes())?;
    let signature: [u8; SIGNATURE_LEN] = raw_signature.try_into().map_err(|_| {
        PolicyError::invalid(format!(
            "COSE Ed25519 signature is {} bytes; expected {SIGNATURE_LEN}",
            raw_signature.len()
        ))
    })?;
    finish(&decoder, body, "COSE_Sign1")?;

    let parsed = ParsedSign1 {
        protected,
        header,
        payload,
        signature,
    };
    if input != encode_sign1(&parsed.protected, &parsed.payload, &parsed.signature)? {
        return Err(PolicyError::NonCanonical("COSE_Sign1"));
    }
    Ok(parsed)
}

pub(crate) fn verify_sign1(
    input: &[u8],
    expected_content_type: ContentType,
    expected_kid: Kid,
    public_key: &Ed25519PublicKey,
) -> Result<Vec<u8>> {
    let parsed = inspect_sign1(input)?;
    if parsed.header.content_type != expected_content_type {
        return Err(PolicyError::invalid(format!(
            "COSE content type {:?} does not match expected {:?}",
            parsed.header.content_type, expected_content_type
        )));
    }
    if parsed.header.kid != expected_kid {
        return Err(PolicyError::invalid(
            "COSE kid does not match the verification key",
        ));
    }
    let to_verify = signature_structure(&parsed.protected, &parsed.payload)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&to_verify, &parsed.signature)
        .map_err(|_| PolicyError::Signature)?;
    Ok(parsed.payload)
}
