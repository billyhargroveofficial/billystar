//! Shared integration-test harness (in-process TCP, no root/TUN).
// Compiled into every test binary; each uses only a subset of the helpers.
#![allow(dead_code)]

use shadowpipe_core::carrier::{client_connect, server_accept, CarrierStream};
use shadowpipe_core::client_auth::{AuthorizedClients, ClientCredential};
use shadowpipe_core::mux::{encode_packet, MuxConfig, Reassembler};
use shadowpipe_core::proto::{CamouflageMode, FrameFlags, PaddingProfile};
use shadowpipe_core::session::{AuthenticatedSession, ClientConfig, ServerState};
use shadowpipe_core::tunnel::{volume_guard_from_config, RotateConnection};
use shadowpipe_core::volume_guard::{VolumeGuard, VolumeGuardConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

pub mod profiles;

pub struct SessionPair {
    pub client: AuthenticatedSession,
    pub server: AuthenticatedSession,
    pub client_stream: CarrierStream<TcpStream>,
    pub server_stream: shadowpipe_core::carrier::MaybePrefixedTcp,
}

pub struct EchoStack {
    pub addr: SocketAddr,
    pub server_fingerprint: [u8; 32],
    pub client_credential: Arc<ClientCredential>,
    _server: tokio::task::JoinHandle<()>,
}

impl EchoStack {
    pub async fn start(camouflage: CamouflageMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(ServerState::generate());
        let server_fingerprint = state.fingerprint();
        let client_credential = Arc::new(ClientCredential::generate().unwrap());
        let authorized_clients =
            Arc::new(AuthorizedClients::from_credentials(&[client_credential.as_ref()]).unwrap());

        let server = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let state = Arc::clone(&state);
                let authorized_clients = Arc::clone(&authorized_clients);
                tokio::spawn(async move {
                    if let Ok(mut stream) = server_accept(tcp).await {
                        if let Ok((mut session, _, _)) = AuthenticatedSession::server_accept(
                            &mut stream,
                            &state,
                            &authorized_clients,
                            camouflage,
                        )
                        .await
                        {
                            loop {
                                match session.recv(&mut stream).await {
                                    Ok((_, flags, _, _)) if flags.contains(FrameFlags::FIN) => {
                                        break;
                                    }
                                    Ok((sid, flags, payload, _)) => {
                                        if flags.contains(FrameFlags::PING) {
                                            let _ = session
                                                .send(&mut stream, sid, FrameFlags::PING, b"pong")
                                                .await;
                                            continue;
                                        }
                                        let _ = session
                                            .send(&mut stream, sid, FrameFlags::DATA, &payload)
                                            .await;
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                });
            }
        });

        // Warm: ensure camouflage matches for client tests
        let _ = camouflage;
        Self {
            addr,
            server_fingerprint,
            client_credential,
            _server: server,
        }
    }

    pub async fn connect(
        &self,
        camouflage: CamouflageMode,
    ) -> (AuthenticatedSession, CarrierStream<TcpStream>) {
        let tcp = TcpStream::connect(self.addr).await.unwrap();
        let mut stream = client_connect(tcp, camouflage).await.unwrap();
        let config = ClientConfig {
            camouflage,
            padding_profile: PaddingProfile::Balanced,
            server_fingerprint: self.server_fingerprint,
            client_credential: Arc::clone(&self.client_credential),
        };
        let (session, _) = AuthenticatedSession::client_connect(&mut stream, &config)
            .await
            .unwrap();
        (session, stream)
    }
}

/// Pump bytes client→server→client (echo) and return received payload.
pub async fn echo_roundtrip(
    session: &mut AuthenticatedSession,
    stream: &mut CarrierStream<TcpStream>,
    payload: &[u8],
) -> Vec<u8> {
    session
        .send(stream, 0, FrameFlags::DATA, payload)
        .await
        .unwrap();
    let (_, flags, reply, _) = session.recv(stream).await.unwrap();
    assert!(flags.contains(FrameFlags::DATA));
    reply
}

/// Mux-framed roundtrip through per-frame echo server (simulates IP packets on wire).
/// Sends and receives one mux frame at a time so TCP buffers cannot deadlock the echo server.
pub async fn mux_echo_roundtrip(
    session: &mut AuthenticatedSession,
    stream: &mut CarrierStream<TcpStream>,
    packet: &[u8],
    mux: &MuxConfig,
    packet_id: u32,
) -> Vec<u8> {
    let frames = encode_packet(packet, packet_id, mux).unwrap();
    let mut reasm = Reassembler::new();
    for (sid, frame) in &frames {
        session
            .send(stream, *sid, FrameFlags::DATA, frame)
            .await
            .unwrap();
        let (_, flags, payload, _) = session.recv(stream).await.unwrap();
        if flags.contains(FrameFlags::FIN) {
            break;
        }
        if let Some(out) = reasm.feed(&payload).unwrap() {
            return out;
        }
    }
    panic!("mux echo incomplete after {} frames", frames.len());
}

/// Fake TUN using channels — enough to exercise run_tunnel_guarded.
pub struct FakeTun {
    inner: Arc<FakeTunInner>,
}

struct FakeTunInner {
    read_buf: Mutex<Vec<u8>>,
    written: Mutex<Vec<Vec<u8>>>,
    mtu: u16,
}

impl FakeTun {
    pub fn new(mtu: u16) -> Self {
        Self {
            inner: Arc::new(FakeTunInner {
                read_buf: Mutex::new(Vec::new()),
                written: Mutex::new(Vec::new()),
                mtu,
            }),
        }
    }

    pub async fn queue_uplink(&self, packet: Vec<u8>) {
        self.inner.read_buf.lock().await.extend(packet);
    }

    pub async fn drain_downlink(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.inner.written.lock().await)
    }
}

impl Clone for FakeTun {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

// Minimal SharedTun stand-in: we use run_tunnel with real SharedTun only in prod;
// for guard+rotation integration use wire-level tests instead.

pub async fn pump_with_volume_guard(
    session: &mut AuthenticatedSession,
    stream: &mut CarrierStream<TcpStream>,
    chunks: &[Vec<u8>],
    guard: &VolumeGuard,
) -> Result<(), RotateConnection> {
    for chunk in chunks {
        let wire = session
            .send(stream, 0, FrameFlags::DATA, chunk)
            .await
            .map_err(|_| RotateConnection)?;
        if guard.record_sent(wire).is_err() {
            return Err(RotateConnection);
        }
        let (_, _, _, rw) = session.recv(stream).await.map_err(|_| RotateConnection)?;
        if guard.record_recv(rw).is_err() {
            return Err(RotateConnection);
        }
    }
    Ok(())
}

pub fn default_mux() -> MuxConfig {
    MuxConfig {
        stream_count: 24,
        max_chunk_size: 1024,
    }
}

pub fn strict_guard(threshold: u64) -> VolumeGuard {
    volume_guard_from_config(VolumeGuardConfig {
        threshold,
        enabled: true,
    })
}

pub async fn send_mux_batch<S>(
    session: &mut AuthenticatedSession,
    stream: &mut S,
    packet: &[u8],
    mux: &MuxConfig,
    packet_id: u32,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for (sid, frame) in encode_packet(packet, packet_id, mux).unwrap() {
        session
            .send(stream, sid, FrameFlags::DATA, &frame)
            .await
            .unwrap();
    }
}

pub async fn recv_mux_packet<S>(
    session: &mut AuthenticatedSession,
    stream: &mut S,
    reasm: &mut Reassembler,
    max_frames: usize,
) -> Option<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for _ in 0..max_frames {
        let (_, flags, payload, _) = session.recv(stream).await.unwrap();
        if flags.contains(FrameFlags::FIN) {
            return None;
        }
        if let Some(p) = reasm.feed(&payload).unwrap() {
            return Some(p);
        }
    }
    None
}
