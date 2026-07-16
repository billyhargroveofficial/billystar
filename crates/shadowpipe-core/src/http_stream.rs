//! Genuine HTTP/2 request/response stream carrier.
//!
//! This is a clean-room Shadowpipe carrier built from RFC 9113 semantics and
//! the public `h2` API. It does not copy Xray's XHTTP wire grammar, constants,
//! defaults, session state machine, or source structure.
//!
//! One client-initiated POST request supplies the uplink body and one `200`
//! response supplies the downlink body. Both bodies remain open concurrently,
//! so the resulting [`HttpStream`] is a full-duplex byte channel suitable for
//! the existing authenticated Shadowpipe session. Unknown authority/path/method
//! requests receive ordinary bounded HTTP responses and never reach inner
//! protocol bytes.
//!
//! This module establishes truthful HTTP/2 framing, bounded flow-control, and a
//! cover response boundary. It is not by itself a production anti-probe claim:
//! production additionally needs a real certificate/origin, replay-safe outer
//! admission, and a reverse-proxy/static-site cover whose timing and behavior
//! are measured against the deployed origin.

use anyhow::{anyhow, Context, Result};
use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode, Version};
use std::future::poll_fn;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf, WriteHalf,
};
use tokio::task::JoinHandle;

pub const MAX_AUTHORITY_BYTES: usize = 253;
pub const MAX_PATH_BYTES: usize = 512;
pub const MIN_OPAQUE_PATH_BYTES: usize = 24;
const BRIDGE_CAPACITY: usize = 256 * 1024;
const PUMP_CHUNK: usize = 16 * 1024;
const COVER_BODY: &[u8] =
    b"<!doctype html><html><head><title>Not Found</title></head><body>Not Found</body></html>";

/// A validated HTTP origin/path tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpStreamRoute {
    authority: String,
    path: String,
}

impl HttpStreamRoute {
    pub fn new(authority: impl Into<String>, path: impl Into<String>) -> Result<Self> {
        let authority = authority.into();
        let path = path.into();
        anyhow::ensure!(
            !authority.is_empty() && authority.len() <= MAX_AUTHORITY_BYTES,
            "HTTP stream authority must contain 1..={MAX_AUTHORITY_BYTES} bytes"
        );
        let parsed_authority: http::uri::Authority = authority
            .parse()
            .context("parse canonical HTTP stream authority")?;
        anyhow::ensure!(
            parsed_authority.as_str() == authority,
            "HTTP stream authority must use its canonical encoding"
        );
        anyhow::ensure!(
            path.len() >= MIN_OPAQUE_PATH_BYTES && path.len() <= MAX_PATH_BYTES,
            "HTTP stream path must contain {MIN_OPAQUE_PATH_BYTES}..={MAX_PATH_BYTES} bytes"
        );
        anyhow::ensure!(
            path.starts_with('/')
                && path
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'#' && byte != b'?'),
            "HTTP stream path must be an absolute visible-ASCII path without query/fragment"
        );
        anyhow::ensure!(
            !path
                .split('/')
                .any(|segment| segment == "." || segment == ".."),
            "HTTP stream path contains a non-canonical dot segment"
        );
        let parsed_path: http::uri::PathAndQuery =
            path.parse().context("parse HTTP stream path")?;
        anyhow::ensure!(
            parsed_path.query().is_none() && parsed_path.path() == path,
            "HTTP stream path must be canonical and query-free"
        );
        Ok(Self { authority, path })
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    fn request_uri(&self) -> Result<http::Uri> {
        format!("https://{}{}", self.authority, self.path)
            .parse()
            .context("construct HTTP/2 stream URI")
    }
}

/// Full-duplex adapter over one HTTP/2 request/response exchange.
///
/// Internal queues are bounded by Tokio's duplex capacity and HTTP/2 flow
/// control. Dropping the adapter aborts its private bridge tasks; it never owns
/// host routes, DNS, firewall state, or TUN lifecycle.
pub struct HttpStream {
    io: DuplexStream,
    /// Dropping a Tokio JoinHandle detaches rather than cancels its task. This
    /// lets the bridge drain already accepted bytes and emit HTTP END_STREAM
    /// after the user-facing duplex side closes.
    _tasks: Vec<JoinHandle<()>>,
}

impl AsyncRead for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

async fn send_bounded(send: &mut SendStream<Bytes>, mut data: Bytes) -> Result<()> {
    while data.has_remaining() {
        send.reserve_capacity(data.remaining().min(PUMP_CHUNK));
        while send.capacity() == 0 {
            let capacity = poll_fn(|cx| send.poll_capacity(cx))
                .await
                .ok_or_else(|| anyhow!("HTTP/2 send stream closed while awaiting capacity"))??;
            anyhow::ensure!(capacity > 0, "HTTP/2 granted zero send capacity");
        }
        let count = send.capacity().min(data.remaining()).min(PUMP_CHUNK);
        send.send_data(data.split_to(count), false)
            .context("send bounded HTTP/2 DATA")?;
    }
    Ok(())
}

async fn upload_pump(
    mut reader: ReadHalf<DuplexStream>,
    mut send: SendStream<Bytes>,
) -> Result<()> {
    let mut buffer = vec![0u8; PUMP_CHUNK];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            send.send_data(Bytes::new(), true)
                .context("finish HTTP/2 upload body")?;
            return Ok(());
        }
        send_bounded(&mut send, Bytes::copy_from_slice(&buffer[..count])).await?;
    }
}

async fn download_pump(mut recv: RecvStream, mut writer: WriteHalf<DuplexStream>) -> Result<()> {
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.context("receive HTTP/2 DATA")?;
        let count = chunk.len();
        writer.write_all(&chunk).await?;
        recv.flow_control()
            .release_capacity(count)
            .context("release HTTP/2 receive capacity")?;
    }
    writer.shutdown().await?;
    Ok(())
}

fn bridge(
    role: &'static str,
    send: SendStream<Bytes>,
    recv: RecvStream,
    mut tasks: Vec<JoinHandle<()>>,
) -> HttpStream {
    let (user, bridge) = tokio::io::duplex(BRIDGE_CAPACITY);
    let (read_from_user, write_to_user) = tokio::io::split(bridge);
    tasks.push(tokio::spawn(async move {
        if let Err(error) = upload_pump(read_from_user, send).await {
            tracing::debug!(%error, %role, "HTTP stream upload pump closed");
        }
    }));
    tasks.push(tokio::spawn(async move {
        if let Err(error) = download_pump(recv, write_to_user).await {
            tracing::debug!(%error, %role, "HTTP stream download pump closed");
        }
    }));
    HttpStream {
        io: user,
        _tasks: tasks,
    }
}

/// Establish a genuine HTTP/2 POST request and expose its request/response
/// bodies as one full-duplex byte stream.
pub async fn client_connect<T>(io: T, route: &HttpStreamRoute) -> Result<HttpStream>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(BRIDGE_CAPACITY as u32)
        .initial_connection_window_size((BRIDGE_CAPACITY * 2) as u32)
        .max_frame_size(PUMP_CHUNK as u32);
    let (mut sender, connection) = builder
        .handshake(io)
        .await
        .context("HTTP/2 client preface")?;
    let driver = tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "HTTP stream client driver closed");
        }
    });
    sender = sender.ready().await.context("HTTP/2 request capacity")?;
    let request = Request::builder()
        .method(Method::POST)
        .version(Version::HTTP_2)
        .uri(route.request_uri()?)
        .header("accept", "application/octet-stream")
        .header("content-type", "application/octet-stream")
        .header("cache-control", "no-store")
        .body(())
        .context("build HTTP/2 stream request")?;
    let (response, send) = sender
        .send_request(request, false)
        .context("send HTTP/2 stream request")?;
    let response = response.await.context("receive HTTP/2 stream response")?;
    anyhow::ensure!(
        response.status() == StatusCode::OK,
        "HTTP/2 stream admission returned {}",
        response.status()
    );
    anyhow::ensure!(
        response.version() == Version::HTTP_2,
        "HTTP stream response was not HTTP/2"
    );
    Ok(bridge("client", send, response.into_body(), vec![driver]))
}

fn cover_status<T>(request: &Request<T>, route: &HttpStreamRoute) -> StatusCode {
    if request.version() != Version::HTTP_2 {
        return StatusCode::HTTP_VERSION_NOT_SUPPORTED;
    }
    if request.uri().authority().map(|value| value.as_str()) != Some(route.authority()) {
        return StatusCode::MISDIRECTED_REQUEST;
    }
    if request.uri().path() != route.path() {
        return StatusCode::NOT_FOUND;
    }
    if request.method() != Method::POST {
        return StatusCode::METHOD_NOT_ALLOWED;
    }
    if request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        != Some("application/octet-stream")
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE;
    }
    StatusCode::OK
}

fn cover_response(status: StatusCode) -> Result<Response<()>> {
    Response::builder()
        .status(status)
        .version(Version::HTTP_2)
        .header("content-type", "text/html; charset=utf-8")
        .header("cache-control", "no-store")
        .body(())
        .context("build HTTP/2 cover response")
}

/// Accept exactly one matching HTTP/2 request. Any mismatch receives an
/// ordinary bounded cover response and returns an error without exposing an
/// inner byte stream.
pub async fn server_accept<T>(io: T, route: &HttpStreamRoute) -> Result<HttpStream>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(BRIDGE_CAPACITY as u32)
        .initial_connection_window_size((BRIDGE_CAPACITY * 2) as u32)
        .max_frame_size(PUMP_CHUNK as u32)
        .max_concurrent_streams(1);
    let mut connection = builder
        .handshake(io)
        .await
        .context("HTTP/2 server preface")?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or_else(|| anyhow!("HTTP/2 peer closed before its request"))?
        .context("accept HTTP/2 stream request")?;
    let status = cover_status(&request, route);
    if status != StatusCode::OK {
        let mut send = respond
            .send_response(cover_response(status)?, false)
            .context("send HTTP/2 cover response headers")?;
        send_bounded(&mut send, Bytes::from_static(COVER_BODY)).await?;
        send.send_data(Bytes::new(), true)
            .context("finish HTTP/2 cover response")?;
        tokio::spawn(async move {
            let _ = poll_fn(|cx| connection.poll_closed(cx)).await;
        });
        return Err(anyhow!("HTTP/2 stream request rejected with {status}"));
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_2)
        .header("content-type", "application/octet-stream")
        .header("cache-control", "no-store")
        .body(())
        .context("build HTTP/2 stream response")?;
    let send = respond
        .send_response(response, false)
        .context("send HTTP/2 stream response")?;
    let recv = request.into_body();
    let driver = tokio::spawn(async move {
        let _ = poll_fn(|cx| connection.poll_closed(cx)).await;
    });
    Ok(bridge("server", send, recv, vec![driver]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_validation_is_bounded_and_canonical() {
        assert!(HttpStreamRoute::new("example.com", "/api/0123456789abcdef01234567").is_ok());
        assert!(HttpStreamRoute::new("", "/api/0123456789abcdef01234567").is_err());
        assert!(HttpStreamRoute::new("example.com", "/short").is_err());
        assert!(HttpStreamRoute::new("example.com", "/api/../0123456789abcdef01234567").is_err());
        assert!(HttpStreamRoute::new("example.com", "/api/0123456789abcdef01234567?q=1").is_err());
    }
}
