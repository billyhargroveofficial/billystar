use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use shadowpipe_core::signed_policy::{
    EndpointId, EndpointPolicyV2, EvidenceHash, KeyStatus, KeysetV1, Kid, OnlineKeyV1, PinStatus,
    PolicyRuleV2, RealityEndpointV2, RuleAction, ServerPinV2, ServiceId, ServiceV2, TransportV2,
    TrustedRoot, VerifiedKeysetArtifact, KEYSET_SCHEMA_VERSION, POLICY_SCHEMA_VERSION,
};

const IDENTITY_DOCUMENT_SCHEMA_VERSION: u64 = 1;
const KEYSET_DOCUMENT_SCHEMA_VERSION: u64 = KEYSET_SCHEMA_VERSION;
const ENDPOINT_POLICY_DOCUMENT_SCHEMA_VERSION: u64 = POLICY_SCHEMA_VERSION;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityKind {
    OfflineRoot,
    OnlinePolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDocument {
    pub schema_version: u64,
    pub kind: IdentityKind,
    pub kid: String,
    pub ed25519_public_key: String,
}

impl IdentityDocument {
    pub fn new(kind: IdentityKind, kid: Kid, public_key: [u8; 32]) -> Self {
        Self {
            schema_version: IDENTITY_DOCUMENT_SCHEMA_VERSION,
            kind,
            kid: hex::encode(kid.as_bytes()),
            ed25519_public_key: hex::encode(public_key),
        }
    }

    pub fn validate(&self, expected_kind: IdentityKind) -> Result<(Kid, [u8; 32])> {
        anyhow::ensure!(
            self.schema_version == IDENTITY_DOCUMENT_SCHEMA_VERSION,
            "unsupported identity document schema {}",
            self.schema_version
        );
        anyhow::ensure!(
            self.kind == expected_kind,
            "identity kind {:?} does not match expected {:?}",
            self.kind,
            expected_kind
        );
        Ok((
            Kid(parse_fixed_hex(&self.kid, "identity kid")?),
            parse_fixed_hex(&self.ed25519_public_key, "Ed25519 public key")?,
        ))
    }

    pub fn as_root_trust(&self) -> Result<TrustedRoot> {
        let (kid, ed25519_public_key) = self.validate(IdentityKind::OfflineRoot)?;
        Ok(TrustedRoot {
            kid,
            ed25519_public_key,
        })
    }

    pub fn as_online_identity(&self) -> Result<(Kid, [u8; 32])> {
        self.validate(IdentityKind::OnlinePolicy)
    }

    pub fn to_pretty_json(&self) -> Result<Vec<u8>> {
        let mut encoded = serde_json::to_vec_pretty(self).context("encode identity JSON")?;
        encoded.push(b'\n');
        Ok(encoded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatusDocument {
    Active,
    Retiring,
    Revoked,
}

impl From<KeyStatusDocument> for KeyStatus {
    fn from(value: KeyStatusDocument) -> Self {
        match value {
            KeyStatusDocument::Active => Self::Active,
            KeyStatusDocument::Retiring => Self::Retiring,
            KeyStatusDocument::Revoked => Self::Revoked,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnlineKeyDocument {
    pub kid: String,
    pub ed25519_public_key: String,
    pub not_before: i64,
    pub expires_at: i64,
    pub status: KeyStatusDocument,
    pub status_since: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysetDocument {
    pub schema_version: u64,
    pub keyset_epoch: u64,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub previous_payload_hash: Option<String>,
    pub keys: Vec<OnlineKeyDocument>,
}

impl KeysetDocument {
    pub fn into_core(self) -> Result<KeysetV1> {
        anyhow::ensure!(
            self.schema_version == KEYSET_DOCUMENT_SCHEMA_VERSION,
            "unsupported keyset document schema {}",
            self.schema_version
        );
        let previous_payload_hash = self
            .previous_payload_hash
            .map(|value| parse_fixed_hex(&value, "previous keyset payload hash"))
            .transpose()?;
        let keys = self
            .keys
            .into_iter()
            .map(|key| {
                Ok(OnlineKeyV1 {
                    kid: Kid(parse_fixed_hex(&key.kid, "online key kid")?),
                    ed25519_public_key: parse_fixed_hex(
                        &key.ed25519_public_key,
                        "online Ed25519 public key",
                    )?,
                    not_before: key.not_before,
                    expires_at: key.expires_at,
                    status: key.status.into(),
                    status_since: key.status_since,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(KeysetV1 {
            keyset_epoch: self.keyset_epoch,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            previous_payload_hash,
            keys,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PinStatusDocument {
    Active,
    Retiring,
}

impl From<PinStatusDocument> for PinStatus {
    fn from(value: PinStatusDocument) -> Self {
        match value {
            PinStatusDocument::Active => Self::Active,
            PinStatusDocument::Retiring => Self::Retiring,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPinDocument {
    pub fingerprint: String,
    pub not_before: i64,
    pub expires_at: i64,
    pub status: PinStatusDocument,
    pub status_since: i64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityEndpointDocument {
    pub endpoint_id: String,
    pub ipv4: Ipv4Addr,
    pub port: u16,
    pub locator_name: String,
    pub sni: String,
    pub reality_x25519_public_key: String,
    pub reality_short_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDocument {
    pub service_id: String,
    pub pins: Vec<ServerPinDocument>,
    pub endpoints: Vec<RealityEndpointDocument>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointPolicyDocument {
    pub schema_version: u64,
    pub policy_epoch: u64,
    pub sequence: u64,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub previous_payload_hash: Option<String>,
    pub services: Vec<ServiceDocument>,
    pub experiment_evidence: Vec<String>,
}

impl EndpointPolicyDocument {
    pub fn into_core(self, keyset: &VerifiedKeysetArtifact) -> Result<EndpointPolicyV2> {
        anyhow::ensure!(
            self.schema_version == ENDPOINT_POLICY_DOCUMENT_SCHEMA_VERSION,
            "unsupported endpoint-policy document schema {}; only schema {} is accepted",
            self.schema_version,
            ENDPOINT_POLICY_DOCUMENT_SCHEMA_VERSION
        );
        let previous_payload_hash = self
            .previous_payload_hash
            .map(|value| parse_fixed_hex(&value, "previous policy payload hash"))
            .transpose()?;
        let services = self
            .services
            .into_iter()
            .map(|service| {
                let service_id = ServiceId(parse_fixed_hex(&service.service_id, "service id")?);
                let pins = service
                    .pins
                    .into_iter()
                    .map(|pin| {
                        Ok(ServerPinV2 {
                            fingerprint: parse_fixed_hex(
                                &pin.fingerprint,
                                "ML-KEM server fingerprint",
                            )?,
                            not_before: pin.not_before,
                            expires_at: pin.expires_at,
                            status: pin.status.into(),
                            status_since: pin.status_since,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let endpoints = service
                    .endpoints
                    .into_iter()
                    .map(|endpoint| {
                        Ok(RealityEndpointV2 {
                            endpoint_id: EndpointId(parse_fixed_hex(
                                &endpoint.endpoint_id,
                                "endpoint id",
                            )?),
                            transport: TransportV2::RealityTcp,
                            ipv4: endpoint.ipv4,
                            port: endpoint.port,
                            locator_name: endpoint.locator_name,
                            sni: endpoint.sni,
                            reality_x25519_public_key: parse_fixed_hex(
                                &endpoint.reality_x25519_public_key,
                                "REALITY X25519 public key",
                            )?,
                            reality_short_id: parse_short_id(&endpoint.reality_short_id)?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(ServiceV2 {
                    service_id,
                    pins,
                    endpoints,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let service_ids = services.iter().map(|service| service.service_id).collect();
        let experiment_evidence = self
            .experiment_evidence
            .into_iter()
            .map(|value| {
                Ok(EvidenceHash(parse_fixed_hex(
                    &value,
                    "experiment evidence hash",
                )?))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(EndpointPolicyV2 {
            keyset_epoch: keyset.keyset().keyset_epoch,
            keyset_payload_hash: *keyset.payload_hash(),
            policy_epoch: self.policy_epoch,
            sequence: self.sequence,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            previous_payload_hash,
            services,
            rules: vec![PolicyRuleV2 {
                action: RuleAction::ProtectedOnly,
                service_ids,
            }],
            experiment_evidence,
        })
    }
}

pub fn parse_json<T: for<'de> Deserialize<'de>>(input: &[u8], what: &str) -> Result<T> {
    serde_json::from_slice(input).with_context(|| format!("parse strict {what} JSON"))
}

pub fn parse_optional_kid(value: Option<&str>) -> Result<Option<Kid>> {
    value
        .map(|value| parse_fixed_hex(value, "kid").map(Kid))
        .transpose()
}

fn parse_fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    anyhow::ensure!(
        value.len() == N * 2,
        "{what} is {} hex characters; expected {}",
        value.len(),
        N * 2
    );
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{what} must use canonical lower-case hexadecimal"
    );
    let decoded = hex::decode(value).with_context(|| format!("decode {what}"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} has the wrong decoded length"))
}

fn parse_short_id(value: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(
        value.len() == 16,
        "production REALITY short id must contain exactly 8 bytes"
    );
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "REALITY short id must use canonical lower-case hexadecimal"
    );
    hex::decode(value).context("decode REALITY short id")
}
