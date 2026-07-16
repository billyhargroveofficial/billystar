use super::error::{PolicyError, Result};
use super::schema::{KeyStatus, KeysetV1, PinStatus, ServiceV2, MIN_ROTATION_OVERLAP_SECS};
use super::verify::{VerifiedBundle, VerifiedKeysetArtifact};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedPolicyState {
    pub(crate) accepted: VerifiedBundle,
    pub(crate) max_issued_at: i64,
    pub(crate) max_wall_clock_seen: i64,
}

impl AcceptedPolicyState {
    pub fn accepted(&self) -> &VerifiedBundle {
        &self.accepted
    }

    pub fn plan(&self) -> &super::plan::VerifiedRealityPlan {
        self.accepted.plan()
    }

    pub fn max_issued_at(&self) -> i64 {
        self.max_issued_at
    }

    pub fn max_wall_clock_seen(&self) -> i64 {
        self.max_wall_clock_seen
    }

    pub fn into_plan(self) -> super::plan::VerifiedRealityPlan {
        self.accepted.into_plan()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transition {
    Applied(AcceptedPolicyState),
    Idempotent(AcceptedPolicyState),
}

impl Transition {
    pub fn state(&self) -> &AcceptedPolicyState {
        match self {
            Self::Applied(state) | Self::Idempotent(state) => state,
        }
    }

    pub fn into_state(self) -> AcceptedPolicyState {
        match self {
            Self::Applied(state) | Self::Idempotent(state) => state,
        }
    }
}

fn elapsed_at_least(later: i64, earlier: i64, minimum: i64) -> bool {
    later
        .checked_sub(earlier)
        .map(|elapsed| elapsed >= minimum)
        .unwrap_or(false)
}

fn required_overlap_end(issued_at: i64) -> Result<i64> {
    issued_at
        .checked_add(MIN_ROTATION_OVERLAP_SECS)
        .ok_or_else(|| PolicyError::Rotation("rotation overlap deadline overflowed".into()))
}

fn ensure_live_at_apply(candidate: &VerifiedBundle, now: i64) -> Result<()> {
    if now < 0 {
        return Err(PolicyError::invalid(
            "policy application time must be non-negative Unix seconds",
        ));
    }
    if candidate.keyset.issued_at > now.saturating_add(super::schema::MAX_CLOCK_SKEW_SECS)
        || candidate.policy.issued_at > now.saturating_add(super::schema::MAX_CLOCK_SKEW_SECS)
    {
        return Err(PolicyError::invalid(
            "signed object issued_at exceeds the allowed apply-time clock skew",
        ));
    }
    if now < candidate.keyset.not_before {
        return Err(PolicyError::NotYetValid("online-key set"));
    }
    if now >= candidate.keyset.expires_at {
        return Err(PolicyError::Expired("online-key set"));
    }
    if now < candidate.policy.not_before {
        return Err(PolicyError::NotYetValid("endpoint policy"));
    }
    if now >= candidate.policy.expires_at {
        return Err(PolicyError::Expired("endpoint policy"));
    }
    let signer = candidate
        .keyset
        .keys
        .iter()
        .find(|key| key.kid == candidate.signer_kid)
        .ok_or_else(|| PolicyError::invalid("verified signer disappeared from keyset"))?;
    if now < signer.not_before {
        return Err(PolicyError::NotYetValid("policy signer key"));
    }
    if now >= signer.expires_at {
        return Err(PolicyError::Expired("policy signer key"));
    }
    Ok(())
}

fn validate_key_rotation(previous: &KeysetV1, candidate: &KeysetV1) -> Result<()> {
    let mut has_live_overlap = false;
    let overlap_end = required_overlap_end(candidate.issued_at)?;
    for old in &previous.keys {
        match candidate.keys.iter().find(|new| new.kid == old.kid) {
            Some(new) => {
                if new.ed25519_public_key != old.ed25519_public_key
                    || new.not_before != old.not_before
                    || new.expires_at != old.expires_at
                {
                    return Err(PolicyError::Rotation(format!(
                        "online key {:?} changed immutable key material or lifetime",
                        old.kid
                    )));
                }
                if matches!(old.status, KeyStatus::Active | KeyStatus::Retiring)
                    && matches!(new.status, KeyStatus::Active | KeyStatus::Retiring)
                    && old.expires_at >= overlap_end
                    && candidate.expires_at >= overlap_end
                {
                    has_live_overlap = true;
                }
                match (old.status, new.status) {
                    (same_old, same_new) if same_old == same_new => {
                        if new.status_since != old.status_since {
                            return Err(PolicyError::Rotation(format!(
                                "online key {:?} changed status_since without a status change",
                                old.kid
                            )));
                        }
                    }
                    (KeyStatus::Active, KeyStatus::Retiring) => {
                        if new.status_since != candidate.issued_at
                            || old.expires_at < overlap_end
                            || candidate.expires_at < overlap_end
                        {
                            return Err(PolicyError::Rotation(format!(
                                "retiring online key {:?} must set status_since to keyset issued_at and remain usable for the complete overlap",
                                old.kid
                            )));
                        }
                    }
                    (KeyStatus::Retiring, KeyStatus::Revoked) => {
                        if new.status_since != candidate.issued_at
                            || !elapsed_at_least(
                                candidate.issued_at,
                                old.status_since,
                                MIN_ROTATION_OVERLAP_SECS,
                            )
                        {
                            return Err(PolicyError::Rotation(format!(
                                "online key {:?} was revoked before the required overlap elapsed",
                                old.kid
                            )));
                        }
                    }
                    _ => {
                        return Err(PolicyError::Rotation(format!(
                            "online key {:?} made a forbidden status transition {:?}->{:?}",
                            old.kid, old.status, new.status
                        )));
                    }
                }
            }
            None => match old.status {
                KeyStatus::Revoked => {}
                KeyStatus::Retiring
                    if elapsed_at_least(
                        candidate.issued_at,
                        old.status_since,
                        MIN_ROTATION_OVERLAP_SECS,
                    ) => {}
                _ => {
                    return Err(PolicyError::Rotation(format!(
                            "online key {:?} was removed without a completed retiring overlap or prior revocation",
                            old.kid
                        )));
                }
            },
        }
    }

    for new in &candidate.keys {
        if previous.keys.iter().all(|old| old.kid != new.kid)
            && (new.status != KeyStatus::Active || new.status_since != candidate.issued_at)
        {
            return Err(PolicyError::Rotation(format!(
                "new online key {:?} must enter as active at keyset issued_at",
                new.kid
            )));
        }
    }
    if !has_live_overlap {
        return Err(PolicyError::Rotation(
            "successive keysets have no common non-revoked verification key".into(),
        ));
    }
    Ok(())
}

fn validate_pin_rotation(
    previous: &ServiceV2,
    candidate: &ServiceV2,
    candidate_issued_at: i64,
    candidate_expires_at: i64,
) -> Result<()> {
    let mut has_overlap = false;
    let overlap_end = required_overlap_end(candidate_issued_at)?;
    for old in &previous.pins {
        match candidate
            .pins
            .iter()
            .find(|new| new.fingerprint == old.fingerprint)
        {
            Some(new) => {
                has_overlap = true;
                if new.not_before != old.not_before || new.expires_at != old.expires_at {
                    return Err(PolicyError::Rotation(format!(
                        "server pin for service {:?} changed its immutable lifetime",
                        previous.service_id
                    )));
                }
                match (old.status, new.status) {
                    (same_old, same_new) if same_old == same_new => {
                        if new.status_since != old.status_since {
                            return Err(PolicyError::Rotation(format!(
                                "server pin for service {:?} changed status_since without a status change",
                                previous.service_id
                            )));
                        }
                    }
                    (PinStatus::Active, PinStatus::Retiring) => {
                        if new.status_since != candidate_issued_at
                            || old.expires_at < overlap_end
                            || candidate_expires_at < overlap_end
                        {
                            return Err(PolicyError::Rotation(format!(
                                "retiring server pin for service {:?} must set status_since to policy issued_at and remain usable for the complete overlap",
                                previous.service_id
                            )));
                        }
                    }
                    _ => {
                        return Err(PolicyError::Rotation(format!(
                            "server pin for service {:?} made a forbidden status transition {:?}->{:?}",
                            previous.service_id, old.status, new.status
                        )));
                    }
                }
            }
            None => {
                if old.status != PinStatus::Retiring
                    || !elapsed_at_least(
                        candidate_issued_at,
                        old.status_since,
                        MIN_ROTATION_OVERLAP_SECS,
                    )
                {
                    return Err(PolicyError::Rotation(format!(
                        "server pin for service {:?} was removed without a completed retiring overlap",
                        previous.service_id
                    )));
                }
            }
        }
    }
    for new in &candidate.pins {
        if previous
            .pins
            .iter()
            .all(|old| old.fingerprint != new.fingerprint)
        {
            if new.status != PinStatus::Active || new.status_since != candidate_issued_at {
                return Err(PolicyError::Rotation(format!(
                    "new server pin for service {:?} must enter as active at policy issued_at",
                    candidate.service_id
                )));
            }
            if candidate_expires_at < overlap_end {
                return Err(PolicyError::Rotation(format!(
                    "policy adding a server pin for service {:?} expires before the required overlap completes",
                    candidate.service_id
                )));
            }
        }
    }
    if !has_overlap {
        return Err(PolicyError::Rotation(format!(
            "successive policies directly swapped every server pin for service {:?}",
            previous.service_id
        )));
    }
    Ok(())
}

fn check_keyset_coordinate_parts(
    previous: &KeysetV1,
    previous_hash: &[u8; 32],
    candidate: &KeysetV1,
    candidate_hash: &[u8; 32],
) -> Result<bool> {
    let old_epoch = previous.keyset_epoch;
    let new_epoch = candidate.keyset_epoch;
    if new_epoch < old_epoch {
        return Err(PolicyError::Rollback(format!(
            "keyset epoch {new_epoch} is below accepted floor {old_epoch}"
        )));
    }
    if new_epoch == old_epoch {
        if candidate_hash != previous_hash {
            return Err(PolicyError::Fork(format!(
                "two keyset payloads occupy epoch {old_epoch}"
            )));
        }
        if candidate != previous {
            return Err(PolicyError::Fork(
                "equal keyset hashes decoded to different payloads".into(),
            ));
        }
        return Ok(false);
    }
    let expected = old_epoch
        .checked_add(1)
        .ok_or_else(|| PolicyError::Gap("accepted keyset epoch cannot advance".into()))?;
    if new_epoch != expected {
        return Err(PolicyError::Gap(format!(
            "keyset epoch jumped from {old_epoch} to {new_epoch}"
        )));
    }
    if candidate.previous_payload_hash != Some(*previous_hash) {
        return Err(PolicyError::Chain(
            "successor keyset does not name the accepted keyset payload hash".into(),
        ));
    }
    if candidate.issued_at < previous.issued_at {
        return Err(PolicyError::Rollback(
            "successor keyset issued_at moved backwards".into(),
        ));
    }
    validate_key_rotation(previous, candidate)?;
    Ok(true)
}

fn check_keyset_coordinate(previous: &VerifiedBundle, candidate: &VerifiedBundle) -> Result<bool> {
    check_keyset_coordinate_parts(
        &previous.keyset,
        &previous.keyset_hash,
        &candidate.keyset,
        &candidate.keyset_hash,
    )
}

/// Validate an offline-root-signed keyset successor against the keyset in an
/// explicitly verified accepted bundle. This is the same epoch/hash/rotation
/// path used by [`apply_verified_update`], but is available before an online
/// signer has produced the matching successor policy.
pub fn validate_keyset_successor(
    previous: &VerifiedBundle,
    candidate: &VerifiedKeysetArtifact,
) -> Result<()> {
    if candidate.root_id() != previous.root_id() {
        return Err(PolicyError::Rotation(
            "offline-root identity changed; root rotation requires a software trust-store update"
                .into(),
        ));
    }
    if !check_keyset_coordinate_parts(
        previous.keyset(),
        previous.keyset_hash(),
        candidate.keyset(),
        candidate.payload_hash(),
    )? {
        return Err(PolicyError::Fork(
            "successor keyset command must advance the keyset epoch".into(),
        ));
    }
    Ok(())
}

fn check_policy_coordinate(previous: &VerifiedBundle, candidate: &VerifiedBundle) -> Result<bool> {
    let old_epoch = previous.policy.policy_epoch;
    let old_sequence = previous.policy.sequence;
    let new_epoch = candidate.policy.policy_epoch;
    let new_sequence = candidate.policy.sequence;

    if new_epoch < old_epoch || (new_epoch == old_epoch && new_sequence < old_sequence) {
        return Err(PolicyError::Rollback(format!(
            "policy coordinate ({new_epoch},{new_sequence}) is below accepted floor ({old_epoch},{old_sequence})"
        )));
    }
    if new_epoch == old_epoch && new_sequence == old_sequence {
        if candidate.policy_hash != previous.policy_hash {
            return Err(PolicyError::Fork(format!(
                "two policy payloads occupy coordinate ({old_epoch},{old_sequence})"
            )));
        }
        if candidate.policy != previous.policy {
            return Err(PolicyError::Fork(
                "equal policy hashes decoded to different payloads".into(),
            ));
        }
        return Ok(false);
    }

    if new_epoch == old_epoch {
        let expected = old_sequence
            .checked_add(1)
            .ok_or_else(|| PolicyError::Gap("policy sequence cannot advance".into()))?;
        if new_sequence != expected {
            return Err(PolicyError::Gap(format!(
                "policy sequence jumped from {old_sequence} to {new_sequence}"
            )));
        }
    } else {
        let expected_epoch = old_epoch
            .checked_add(1)
            .ok_or_else(|| PolicyError::Gap("policy epoch cannot advance".into()))?;
        if new_epoch != expected_epoch || new_sequence != 0 {
            return Err(PolicyError::Gap(format!(
                "policy epoch transition ({old_epoch},{old_sequence})->({new_epoch},{new_sequence}) is not the next epoch at sequence zero"
            )));
        }
    }
    if candidate.policy.previous_payload_hash != Some(previous.policy_hash) {
        return Err(PolicyError::Chain(
            "successor policy does not name the accepted policy payload hash".into(),
        ));
    }
    if candidate.policy.issued_at < previous.policy.issued_at {
        return Err(PolicyError::Rollback(
            "successor policy issued_at moved backwards".into(),
        ));
    }

    let previous_service_ids: Vec<_> = previous
        .policy
        .services
        .iter()
        .map(|service| service.service_id)
        .collect();
    let candidate_service_ids: Vec<_> = candidate
        .policy
        .services
        .iter()
        .map(|service| service.service_id)
        .collect();
    if candidate_service_ids != previous_service_ids {
        return Err(PolicyError::Rotation(
            "endpoint-policy v2 keeps the exact enrolled service_id set immutable; adding, removing, or renaming service authority requires a new authenticated enrollment"
                .into(),
        ));
    }
    for (old_service, new_service) in previous
        .policy
        .services
        .iter()
        .zip(&candidate.policy.services)
    {
        validate_pin_rotation(
            old_service,
            new_service,
            candidate.policy.issued_at,
            candidate.policy.expires_at,
        )?;
    }
    Ok(true)
}

pub fn apply_verified_update(
    previous: Option<&AcceptedPolicyState>,
    candidate: VerifiedBundle,
    now: i64,
) -> Result<Transition> {
    let candidate_max_issued = candidate.keyset.issued_at.max(candidate.policy.issued_at);

    let Some(previous) = previous else {
        ensure_live_at_apply(&candidate, now)?;
        if candidate.keyset.keyset_epoch != 0
            || candidate.policy.policy_epoch != 0
            || candidate.policy.sequence != 0
        {
            return Err(PolicyError::Gap(
                "genesis must be keyset epoch 0 and policy coordinate (0,0)".into(),
            ));
        }
        if candidate.keyset.previous_payload_hash.is_some()
            || candidate.policy.previous_payload_hash.is_some()
        {
            return Err(PolicyError::Chain(
                "genesis keyset and policy must not have predecessor hashes".into(),
            ));
        }
        return Ok(Transition::Applied(AcceptedPolicyState {
            accepted: candidate,
            max_issued_at: candidate_max_issued,
            max_wall_clock_seen: now,
        }));
    };

    if now.saturating_add(super::schema::MAX_CLOCK_SKEW_SECS) < previous.max_wall_clock_seen {
        return Err(PolicyError::Rollback(format!(
            "wall clock {now} is behind observed floor {}",
            previous.max_wall_clock_seen
        )));
    }
    ensure_live_at_apply(&candidate, now)?;
    if candidate.root_id != previous.accepted.root_id {
        return Err(PolicyError::Rotation(
            "offline-root identity changed; root rotation requires a software trust-store update"
                .into(),
        ));
    }
    if candidate_max_issued < previous.max_issued_at {
        return Err(PolicyError::Rollback(format!(
            "candidate issued_at floor {candidate_max_issued} is below accepted floor {}",
            previous.max_issued_at
        )));
    }

    let keyset_changed = check_keyset_coordinate(&previous.accepted, &candidate)?;
    let policy_changed = check_policy_coordinate(&previous.accepted, &candidate)?;
    if keyset_changed && !policy_changed {
        return Err(PolicyError::Fork(
            "a new keyset cannot reuse an already occupied policy coordinate".into(),
        ));
    }

    let state = AcceptedPolicyState {
        accepted: candidate,
        max_issued_at: previous.max_issued_at.max(candidate_max_issued),
        max_wall_clock_seen: previous.max_wall_clock_seen.max(now),
    };
    if keyset_changed || policy_changed {
        Ok(Transition::Applied(state))
    } else {
        Ok(Transition::Idempotent(state))
    }
}

/// Validate a candidate as the immediate successor of an explicitly supplied,
/// currently live verified bundle.
///
/// This helper is intended for release tooling that has the public predecessor
/// artifact but not the client's private durable state file. It derives the
/// anti-rollback floors from that predecessor and then delegates to the exact
/// [`apply_verified_update`] transition implementation. Client runtime updates
/// must continue to use their durable [`AcceptedPolicyState`] so clock floors
/// survive restarts.
pub fn apply_verified_successor(
    previous: &VerifiedBundle,
    candidate: VerifiedBundle,
    now: i64,
) -> Result<Transition> {
    ensure_live_at_apply(previous, now)?;
    let previous_max_issued = previous.keyset.issued_at.max(previous.policy.issued_at);
    let previous_state = AcceptedPolicyState {
        accepted: previous.clone(),
        max_issued_at: previous_max_issued,
        max_wall_clock_seen: now,
    };
    apply_verified_update(Some(&previous_state), candidate, now)
}
