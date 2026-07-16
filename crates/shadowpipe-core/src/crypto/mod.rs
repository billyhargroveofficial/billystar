use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    MlKem768,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const MLKEM_PUBLIC_KEY_SIZE: usize = 1184;
pub const MLKEM_CIPHERTEXT_SIZE: usize = 1088;
pub const MLKEM_SEED_SIZE: usize = 64;
pub const MLKEM_LEGACY_EXPANDED_SECRET_SIZE: usize = 2400;

pub type MlkemPublicKey = ml_kem::ml_kem_768::EncapsulationKey;
pub type MlkemSecretKey = ml_kem::ml_kem_768::DecapsulationKey;
pub type MlkemCiphertext = ml_kem::ml_kem_768::Ciphertext;

#[derive(Clone)]
pub struct SessionKeys {
    pub send_key: [u8; KEY_SIZE],
    pub recv_key: [u8; KEY_SIZE],
}

impl Zeroize for SessionKeys {
    fn zeroize(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SessionKeys {}

pub struct MlkemKeypair {
    pub public: MlkemPublicKey,
    pub secret: MlkemSecretKey,
}

impl MlkemKeypair {
    pub fn generate() -> Self {
        let (secret, public) = MlKem768::generate_keypair();
        Self { public, secret }
    }
}

pub struct X25519Keypair {
    pub secret: StaticSecret,
    pub public: X25519Public,
}

impl X25519Keypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = X25519Public::from(&secret);
        Self { secret, public }
    }

    pub fn ephemeral() -> (EphemeralSecret, X25519Public) {
        let secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let public = X25519Public::from(&secret);
        (secret, public)
    }
}

pub fn encapsulate_mlkem(
    server_public: &MlkemPublicKey,
) -> Result<(MlkemCiphertext, Zeroizing<[u8; KEY_SIZE]>)> {
    let (ct, mut shared) = server_public.encapsulate();
    let mut secret = Zeroizing::new([0u8; KEY_SIZE]);
    secret.copy_from_slice(shared.as_ref());
    shared.zeroize();
    Ok((ct, secret))
}

pub fn decapsulate_mlkem(
    server_secret: &MlkemSecretKey,
    ciphertext: &MlkemCiphertext,
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let mut shared = server_secret.decapsulate(ciphertext);
    let mut secret = Zeroizing::new([0u8; KEY_SIZE]);
    secret.copy_from_slice(shared.as_ref());
    shared.zeroize();
    Ok(secret)
}

fn require_contributory_x25519(shared: [u8; KEY_SIZE]) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let shared = Zeroizing::new(shared);
    let nonzero = shared
        .iter()
        .fold(0u8, |accumulator, byte| accumulator | byte);
    if nonzero == 0 {
        return Err(anyhow!(
            "non-contributory X25519 public key produced the all-zero shared secret"
        ));
    }
    Ok(shared)
}

/// Perform X25519 and enforce RFC 7748's all-zero output check.  A low-order
/// peer share must not silently remove the classical component from the hybrid
/// key schedule.
pub fn x25519_shared(
    local: &StaticSecret,
    remote: &X25519Public,
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let shared = local.diffie_hellman(remote);
    require_contributory_x25519(*shared.as_bytes())
}

pub fn x25519_ephemeral_shared(
    local: EphemeralSecret,
    remote: &X25519Public,
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let shared = local.diffie_hellman(remote);
    require_contributory_x25519(*shared.as_bytes())
}

/// Derive directional AEAD keys while borrowing the hybrid shared secrets, so
/// this boundary does not create additional `Copy` stack values. Production
/// callers keep both inputs in [`Zeroizing`] buffers for the full borrow.
struct V3TrafficKeyInputs<'a> {
    x_shared: &'a [u8; KEY_SIZE],
    pq_shared: &'a [u8; KEY_SIZE],
    client_psk: Option<&'a [u8; KEY_SIZE]>,
    client_random: [u8; 16],
    server_random: [u8; 16],
    transcript: &'a [u8; 32],
    client_to_server: bool,
}

fn derive_v3_traffic_keys(domain: &[u8], inputs: V3TrafficKeyInputs<'_>) -> Result<SessionKeys> {
    let seed_capacity = b"shadowpipe-v3/ikm\0".len() + KEY_SIZE * 3 + 16 * 2;
    let mut seed = Zeroizing::new(Vec::with_capacity(seed_capacity));
    seed.extend_from_slice(b"shadowpipe-v3/ikm\0");
    seed.extend_from_slice(inputs.x_shared);
    seed.extend_from_slice(inputs.pq_shared);
    if let Some(client_psk) = inputs.client_psk {
        seed.extend_from_slice(client_psk);
    }
    seed.extend_from_slice(&inputs.client_random);
    seed.extend_from_slice(&inputs.server_random);

    let hk = Hkdf::<Sha256>::new(Some(inputs.transcript), &seed);
    let mut material = Zeroizing::new([0u8; KEY_SIZE * 2]);
    hk.expand(domain, material.as_mut())
        .map_err(|_| anyhow!("hkdf expand failed"))?;

    let mut keys = SessionKeys {
        send_key: [0u8; KEY_SIZE],
        recv_key: [0u8; KEY_SIZE],
    };
    if inputs.client_to_server {
        keys.send_key.copy_from_slice(&material[..KEY_SIZE]);
        keys.recv_key.copy_from_slice(&material[KEY_SIZE..]);
    } else {
        keys.send_key.copy_from_slice(&material[KEY_SIZE..]);
        keys.recv_key.copy_from_slice(&material[..KEY_SIZE]);
    }
    Ok(keys)
}

/// Directional keys used only for the encrypted ClientFinished and
/// ServerFinished records.  These keys have an independent HKDF label and are
/// discarded before application traffic starts, so their nonce zero is never
/// reused with an application key.
pub fn derive_handshake_traffic_keys(
    x_shared: &[u8; KEY_SIZE],
    pq_shared: &[u8; KEY_SIZE],
    client_random: [u8; 16],
    server_random: [u8; 16],
    pre_finished_transcript: &[u8; 32],
    client_to_server: bool,
) -> Result<SessionKeys> {
    derive_v3_traffic_keys(
        b"shadowpipe-v3/handshake-traffic-keys\0",
        V3TrafficKeyInputs {
            x_shared,
            pq_shared,
            client_psk: None,
            client_random,
            server_random,
            transcript: pre_finished_transcript,
            client_to_server,
        },
    )
}

/// Final application keys.  The independent client PSK is mixed directly into
/// the HKDF input and the salt commits to the transcript including both
/// Finished plaintexts.  This is separate from the handshake traffic key
/// schedule and therefore begins with fresh per-direction nonce counters.
pub fn derive_application_traffic_keys(
    x_shared: &[u8; KEY_SIZE],
    pq_shared: &[u8; KEY_SIZE],
    client_psk: &[u8; KEY_SIZE],
    client_random: [u8; 16],
    server_random: [u8; 16],
    finished_transcript: &[u8; 32],
    client_to_server: bool,
) -> Result<SessionKeys> {
    derive_v3_traffic_keys(
        b"shadowpipe-v3/application-traffic-keys\0",
        V3TrafficKeyInputs {
            x_shared,
            pq_shared,
            client_psk: Some(client_psk),
            client_random,
            server_random,
            transcript: finished_transcript,
            client_to_server,
        },
    )
}

pub struct AeadSession {
    send: ChaCha20Poly1305,
    recv: ChaCha20Poly1305,
    send_nonce: u64,
    recv_nonce: u64,
    send_failed: bool,
    recv_failed: bool,
}

/// TX half — safe to lock independently from RX in full-duplex tunnel mode.
pub struct AeadTx {
    cipher: ChaCha20Poly1305,
    nonce: u64,
    failed: bool,
}

/// RX half — safe to lock independently from TX in full-duplex tunnel mode.
pub struct AeadRx {
    cipher: ChaCha20Poly1305,
    nonce: u64,
    failed: bool,
}

impl AeadSession {
    pub fn new(keys: &SessionKeys) -> Result<Self> {
        Ok(Self {
            send: ChaCha20Poly1305::new(&keys.send_key.into()),
            recv: ChaCha20Poly1305::new(&keys.recv_key.into()),
            send_nonce: 0,
            recv_nonce: 0,
            send_failed: false,
            recv_failed: false,
        })
    }

    pub fn split(self) -> (AeadTx, AeadRx) {
        (
            AeadTx {
                cipher: self.send,
                nonce: self.send_nonce,
                failed: self.send_failed,
            },
            AeadRx {
                cipher: self.recv,
                nonce: self.recv_nonce,
                failed: self.recv_failed,
            },
        )
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if self.send_failed {
            return Err(anyhow!("AEAD send direction is permanently poisoned"));
        }
        let nonce = nonce_from_counter(self.send_nonce);
        let Some(next_nonce) = self.send_nonce.checked_add(1) else {
            self.send_failed = true;
            return Err(anyhow!("aead send nonce overflow; direction poisoned"));
        };
        match self.send.encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        ) {
            Ok(ciphertext) => {
                self.send_nonce = next_nonce;
                Ok(ciphertext)
            }
            Err(error) => {
                self.send_failed = true;
                Err(anyhow!("encrypt frame: {error}; send direction poisoned"))
            }
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if self.recv_failed {
            return Err(anyhow!("AEAD receive direction is permanently poisoned"));
        }
        let nonce = nonce_from_counter(self.recv_nonce);
        let Some(next_nonce) = self.recv_nonce.checked_add(1) else {
            self.recv_failed = true;
            return Err(anyhow!("aead receive nonce overflow; direction poisoned"));
        };
        match self.recv.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        ) {
            Ok(plaintext) => {
                self.recv_nonce = next_nonce;
                Ok(plaintext)
            }
            Err(error) => {
                self.recv_failed = true;
                Err(anyhow!(
                    "decrypt frame: {error}; receive direction poisoned"
                ))
            }
        }
    }
}

impl AeadTx {
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err(anyhow!("AEAD send direction is permanently poisoned"));
        }
        let nonce = nonce_from_counter(self.nonce);
        let Some(next_nonce) = self.nonce.checked_add(1) else {
            self.failed = true;
            return Err(anyhow!("aead send nonce overflow; direction poisoned"));
        };
        match self.cipher.encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        ) {
            Ok(ciphertext) => {
                self.nonce = next_nonce;
                Ok(ciphertext)
            }
            Err(error) => {
                self.failed = true;
                Err(anyhow!("encrypt frame: {error}; send direction poisoned"))
            }
        }
    }
}

impl AeadRx {
    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if self.failed {
            return Err(anyhow!("AEAD receive direction is permanently poisoned"));
        }
        let nonce = nonce_from_counter(self.nonce);
        let Some(next_nonce) = self.nonce.checked_add(1) else {
            self.failed = true;
            return Err(anyhow!("aead receive nonce overflow; direction poisoned"));
        };
        match self.cipher.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        ) {
            Ok(plaintext) => {
                self.nonce = next_nonce;
                Ok(plaintext)
            }
            Err(error) => {
                self.failed = true;
                Err(anyhow!(
                    "decrypt frame: {error}; receive direction poisoned"
                ))
            }
        }
    }
}

fn nonce_from_counter(counter: u64) -> Nonce {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(nonce)
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn random_session_id() -> [u8; 8] {
    random_bytes()
}

/// Stable identity fingerprint of a server ML-KEM public key, for client-side pinning.
/// Domain-separated SHA-256 so a client can verify the key on the wire is the real server's.
pub fn mlkem_fingerprint(pk_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"shadowpipe-mlkem-id-v1");
    h.update(pk_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Constant-time byte equality (no early-out on first differing byte).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn mlkem_public_bytes(pk: &MlkemPublicKey) -> Vec<u8> {
    pk.to_bytes().to_vec()
}

/// Preferred serialization for freshly generated ML-KEM keys is the 64-byte
/// FIPS 203 seed. A key loaded through the compatibility-only expanded-key
/// path has no recoverable seed, so preserve its validated expanded encoding
/// if it ever needs to be saved again.
#[allow(deprecated)]
pub fn mlkem_secret_storage_bytes(sk: &MlkemSecretKey) -> Zeroizing<Vec<u8>> {
    use ml_kem::ExpandedKeyEncoding;

    if let Some(mut seed) = sk.to_seed() {
        let encoded = Zeroizing::new(seed.to_vec());
        seed.zeroize();
        encoded
    } else {
        let mut expanded = sk.to_expanded_bytes();
        let encoded = Zeroizing::new(expanded.to_vec());
        expanded.zeroize();
        encoded
    }
}

pub fn mlkem_ciphertext_from_bytes(bytes: &[u8]) -> Result<MlkemCiphertext> {
    bytes.try_into().map_err(|_| {
        anyhow!(
            "invalid mlkem ciphertext length: got {}, expected {}",
            bytes.len(),
            MLKEM_CIPHERTEXT_SIZE
        )
    })
}

pub fn mlkem_public_from_bytes(bytes: &[u8]) -> Result<MlkemPublicKey> {
    let encoded: ml_kem::Key<MlkemPublicKey> = bytes.try_into().map_err(|_| {
        anyhow!(
            "invalid mlkem public key length: got {}, expected {}",
            bytes.len(),
            MLKEM_PUBLIC_KEY_SIZE
        )
    })?;
    MlkemPublicKey::new(&encoded).map_err(|_| anyhow!("invalid mlkem public key encoding"))
}

/// Decode either the preferred 64-byte seed form written by current versions,
/// or the 2400-byte expanded FIPS 203 form written by the former
/// `pqcrypto-mlkem` backend. Expanded keys are validated by RustCrypto before
/// being accepted (including the embedded public-key hash).
#[allow(deprecated)]
pub fn mlkem_secret_from_storage_bytes(bytes: &[u8]) -> Result<MlkemSecretKey> {
    use ml_kem::ExpandedKeyEncoding;

    match bytes.len() {
        MLKEM_SEED_SIZE => {
            let seed: Zeroizing<ml_kem::Seed> = Zeroizing::new(
                bytes
                    .try_into()
                    .map_err(|_| anyhow!("invalid mlkem seed length"))?,
            );
            Ok(MlkemSecretKey::from_seed(*seed))
        }
        MLKEM_LEGACY_EXPANDED_SECRET_SIZE => {
            let expanded: Zeroizing<ml_kem::ExpandedDecapsulationKey<MlKem768>> = Zeroizing::new(
                bytes
                    .try_into()
                    .map_err(|_| anyhow!("invalid expanded mlkem secret key length"))?,
            );
            let secret = MlkemSecretKey::from_expanded_bytes(&expanded)
                .map_err(|_| anyhow!("invalid expanded mlkem secret key encoding"))?;
            validate_mlkem_keypair(&secret)?;
            Ok(secret)
        }
        actual => Err(anyhow!(
            "invalid mlkem secret key length: got {actual}, expected {MLKEM_SEED_SIZE} (seed) or \
             {MLKEM_LEGACY_EXPANDED_SECRET_SIZE} (legacy expanded)"
        )),
    }
}

/// Pairwise consistency check for compatibility-only expanded private keys.
///
/// RustCrypto validates the embedded public-key encoding and hash when it
/// imports the legacy expanded form, but that format cannot reconstruct the
/// public key from the private PKE component. A deterministic encapsulation and
/// decapsulation catches disk corruption or a mismatched private component
/// before the server advertises the still-valid embedded public identity.
fn validate_mlkem_keypair(secret: &MlkemSecretKey) -> Result<()> {
    let public = secret.encapsulation_key();
    let mut h = Sha256::new();
    h.update(b"shadowpipe-mlkem-expanded-pairwise-check-v1");
    h.update(public.to_bytes());
    let message_bytes: [u8; KEY_SIZE] = h.finalize().into();
    let message: ml_kem::B32 = message_bytes.into();
    let (ciphertext, mut encapsulated) = public.encapsulate_deterministic(&message);
    let mut decapsulated = secret.decapsulate(&ciphertext);
    let matches = ct_eq(encapsulated.as_slice(), decapsulated.as_slice());
    encapsulated.zeroize();
    decapsulated.zeroize();
    if !matches {
        return Err(anyhow!(
            "expanded mlkem secret key failed pairwise encapsulation self-test"
        ));
    }
    Ok(())
}

pub fn mlkem_derived_public_bytes(sk: &MlkemSecretKey) -> Vec<u8> {
    sk.encapsulation_key().to_bytes().to_vec()
}

pub fn x25519_public_from_bytes(bytes: [u8; KEY_SIZE]) -> X25519Public {
    X25519Public::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_requires_a_contributory_peer_share() {
        let local = StaticSecret::from([0x42; KEY_SIZE]);
        let low_order = X25519Public::from([0u8; KEY_SIZE]);
        assert!(x25519_shared(&local, &low_order).is_err());

        let alice = X25519Keypair::generate();
        let bob = X25519Keypair::generate();
        let alice_shared = x25519_shared(&alice.secret, &bob.public).unwrap();
        let bob_shared = x25519_shared(&bob.secret, &alice.public).unwrap();
        assert!(ct_eq(alice_shared.as_ref(), bob_shared.as_ref()));
    }

    #[test]
    fn aead_authentication_failure_permanently_poison_receive_state() {
        let keys = SessionKeys {
            send_key: [0x71; KEY_SIZE],
            recv_key: [0x71; KEY_SIZE],
        };
        let mut sender = AeadSession::new(&keys).unwrap();
        let mut first = sender.encrypt(b"first", b"record-0").unwrap();
        let second = sender.encrypt(b"second", b"record-1").unwrap();
        first[0] ^= 1;

        let mut receiver = AeadSession::new(&keys).unwrap();
        assert!(receiver.decrypt(&first, b"record-0").is_err());
        let terminal = receiver.decrypt(&second, b"record-1").unwrap_err();
        assert!(terminal.to_string().contains("permanently poisoned"));

        let (_, mut split_receiver) = AeadSession::new(&keys).unwrap().split();
        assert!(split_receiver.decrypt(&first, b"record-0").is_err());
        let terminal = split_receiver.decrypt(&second, b"record-1").unwrap_err();
        assert!(terminal.to_string().contains("permanently poisoned"));
    }

    #[test]
    fn aead_nonce_overflow_permanently_poison_send_state() {
        let keys = SessionKeys {
            send_key: [0x82; KEY_SIZE],
            recv_key: [0x82; KEY_SIZE],
        };
        let mut session = AeadSession::new(&keys).unwrap();
        session.send_nonce = u64::MAX;
        assert!(session.encrypt(b"never sent", b"aad").is_err());
        // Even an internal counter reset cannot revive a direction after a
        // terminal nonce/allocation failure; public callers cannot reset it.
        session.send_nonce = 0;
        assert!(session
            .encrypt(b"still forbidden", b"aad")
            .unwrap_err()
            .to_string()
            .contains("permanently poisoned"));

        let (mut split_sender, _) = AeadSession::new(&keys).unwrap().split();
        split_sender.nonce = u64::MAX;
        assert!(split_sender.encrypt(b"never sent", b"aad").is_err());
        split_sender.nonce = 0;
        assert!(split_sender
            .encrypt(b"still forbidden", b"aad")
            .unwrap_err()
            .to_string()
            .contains("permanently poisoned"));
    }
}
