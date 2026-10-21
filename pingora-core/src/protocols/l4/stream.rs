// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Transport layer connection

use async_trait::async_trait;
use futures::FutureExt;
use log::{debug, error};

use pingora_error::{ErrorType::*, OrErr, Result};
#[cfg(target_os = "linux")]
use std::io::IoSliceMut;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime};
#[cfg(target_os = "linux")]
use tokio::io::Interest;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, ReadBuf};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;

use crate::protocols::l4::ext::{set_tcp_keepalive, TcpKeepalive};
use crate::protocols::l4::virt;
use crate::protocols::raw_connect::ProxyDigest;
use crate::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl,
    TimingDigest, UniqueID, UniqueIDType,
};
use crate::upstreams::peer::Tracer;

#[derive(Debug)]
enum RawStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
    Virtual(virt::VirtualSocketStream),
}

impl AsyncRead for RawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Safety: Basic enum pin projection
        unsafe {
            match &mut Pin::get_unchecked_mut(self) {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_read(cx, buf),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_read(cx, buf),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_read(cx, buf),
            }
        }
    }
}

impl AsyncWrite for RawStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        // Safety: Basic enum pin projection
        unsafe {
            match &mut Pin::get_unchecked_mut(self) {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_write(cx, buf),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_write(cx, buf),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_write(cx, buf),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // Safety: Basic enum pin projection
        unsafe {
            match &mut Pin::get_unchecked_mut(self) {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_flush(cx),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_flush(cx),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_flush(cx),
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // Safety: Basic enum pin projection
        unsafe {
            match &mut Pin::get_unchecked_mut(self) {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_shutdown(cx),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_shutdown(cx),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_shutdown(cx),
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        // Safety: Basic enum pin projection
        unsafe {
            match &mut Pin::get_unchecked_mut(self) {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_write_vectored(cx, bufs),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_write_vectored(cx, bufs),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_write_vectored(cx, bufs),
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            RawStream::Tcp(s) => s.is_write_vectored(),
            #[cfg(unix)]
            RawStream::Unix(s) => s.is_write_vectored(),
            RawStream::Virtual(s) => s.is_write_vectored(),
        }
    }
}

#[cfg(unix)]
impl AsRawFd for RawStream {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        match self {
            RawStream::Tcp(s) => s.as_raw_fd(),
            RawStream::Unix(s) => s.as_raw_fd(),
            RawStream::Virtual(_) => -1, // Virtual stream does not have a real fd
        }
    }
}

#[cfg(windows)]
impl AsRawSocket for RawStream {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        match self {
            RawStream::Tcp(s) => s.as_raw_socket(),
            // Virtual stream does not have a real socket, return INVALID_SOCKET (!0)
            RawStream::Virtual(_) => !0,
        }
    }
}

#[derive(Debug)]
struct RawStreamWrapper {
    pub(crate) stream: RawStream,
    /// store the last rx timestamp of the stream.
    pub(crate) rx_ts: Option<SystemTime>,
    /// enable reading rx timestamp
    #[cfg(target_os = "linux")]
    pub(crate) enable_rx_ts: bool,
    #[cfg(target_os = "linux")]
    /// This can be reused across multiple recvmsg calls. The cmsg buffer may
    /// come from old sockets created by older version of pingora and so,
    /// this vector can only grow.
    reusable_cmsg_space: Vec<u8>,
}

impl RawStreamWrapper {
    pub fn new(stream: RawStream) -> Self {
        RawStreamWrapper {
            stream,
            rx_ts: None,
            #[cfg(target_os = "linux")]
            enable_rx_ts: false,
            #[cfg(target_os = "linux")]
            reusable_cmsg_space: nix::cmsg_space!(nix::sys::socket::Timestamps),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn enable_rx_ts(&mut self, enable_rx_ts: bool) {
        self.enable_rx_ts = enable_rx_ts;
    }
}

impl AsyncRead for RawStreamWrapper {
    #[cfg(not(target_os = "linux"))]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Safety: Basic enum pin projection
        unsafe {
            let rs_wrapper = Pin::get_unchecked_mut(self);
            match &mut rs_wrapper.stream {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_read(cx, buf),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_read(cx, buf),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_read(cx, buf),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        use futures::ready;
        use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage};

        // if we do not need rx timestamp, then use the standard path
        if !self.enable_rx_ts {
            // Safety: Basic enum pin projection
            unsafe {
                let rs_wrapper = Pin::get_unchecked_mut(self);
                match &mut rs_wrapper.stream {
                    RawStream::Tcp(s) => return Pin::new_unchecked(s).poll_read(cx, buf),
                    RawStream::Unix(s) => return Pin::new_unchecked(s).poll_read(cx, buf),
                    RawStream::Virtual(s) => return Pin::new_unchecked(s).poll_read(cx, buf),
                }
            }
        }

        // Safety: Basic pin projection to get mutable stream
        let rs_wrapper = unsafe { Pin::get_unchecked_mut(self) };
        match &mut rs_wrapper.stream {
            RawStream::Tcp(s) => {
                loop {
                    ready!(s.poll_read_ready(cx))?;
                    // Safety: maybe uninitialized bytes will only be passed to recvmsg
                    let b = unsafe {
                        &mut *(buf.unfilled_mut() as *mut [std::mem::MaybeUninit<u8>]
                            as *mut [u8])
                    };
                    let mut iov = [IoSliceMut::new(b)];

                    rs_wrapper.reusable_cmsg_space.fill(0);

                    match s.try_io(Interest::READABLE, || {
                        recvmsg::<SockaddrStorage>(
                            s.as_raw_fd(),
                            &mut iov,
                            Some(&mut rs_wrapper.reusable_cmsg_space),
                            MsgFlags::empty(),
                        )
                        .map_err(|errno| errno.into())
                    }) {
                        Ok(r) => {
                            if let Some(ControlMessageOwned::ScmTimestampsns(rtime)) = r
                                .cmsgs()?
                                .find(|i| matches!(i, ControlMessageOwned::ScmTimestampsns(_)))
                            {
                                // The returned timestamp is a real (i.e. not monotonic) timestamp
                                // https://docs.kernel.org/networking/timestamping.html
                                rs_wrapper.rx_ts =
                                    SystemTime::UNIX_EPOCH.checked_add(rtime.system.into());
                            }
                            // Safety: We trust `recvmsg` to have filled up `r.bytes` bytes in the buffer.
                            unsafe {
                                buf.assume_init(r.bytes);
                            }
                            buf.advance(r.bytes);
                            return Poll::Ready(Ok(()));
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
            }
            // Unix RX timestamp only works with datagram for now, so we do not care about it
            RawStream::Unix(s) => unsafe { Pin::new_unchecked(s).poll_read(cx, buf) },
            RawStream::Virtual(s) => unsafe { Pin::new_unchecked(s).poll_read(cx, buf) },
        }
    }
}

impl AsyncWrite for RawStreamWrapper {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        // Safety: Basic enum pin projection
        unsafe {
            match &mut Pin::get_unchecked_mut(self).stream {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_write(cx, buf),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_write(cx, buf),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_write(cx, buf),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // Safety: Basic enum pin projection
        unsafe {
            match &mut Pin::get_unchecked_mut(self).stream {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_flush(cx),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_flush(cx),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_flush(cx),
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // Safety: Basic enum pin projection
        unsafe {
            match &mut Pin::get_unchecked_mut(self).stream {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_shutdown(cx),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_shutdown(cx),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_shutdown(cx),
            }
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        // Safety: Basic enum pin projection
        unsafe {
            match &mut Pin::get_unchecked_mut(self).stream {
                RawStream::Tcp(s) => Pin::new_unchecked(s).poll_write_vectored(cx, bufs),
                #[cfg(unix)]
                RawStream::Unix(s) => Pin::new_unchecked(s).poll_write_vectored(cx, bufs),
                RawStream::Virtual(s) => Pin::new_unchecked(s).poll_write_vectored(cx, bufs),
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }
}

#[cfg(unix)]
impl AsRawFd for RawStreamWrapper {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.stream.as_raw_fd()
    }
}

#[cfg(windows)]
impl AsRawSocket for RawStreamWrapper {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        self.stream.as_raw_socket()
    }
}

/// The default L4 read buffer size.
///
/// Large read buffering helps reducing syscalls with little trade-off. The SSL
/// layer always does "small" reads in 16k chunks (TLS record size), so L4 read
/// buffering helps a lot.
pub const DEFAULT_L4_READ_BUFFER_SIZE: usize = 64 * 1024;

/// The default L4 write buffer size.
///
/// Small write buffering matches a typical MSS. Too large a write buffer delays
/// real-time communication. This buffering effectively implements something
/// similar to Nagle's algorithm, but user space can control when to flush.
pub const DEFAULT_L4_WRITE_BUFFER_SIZE: usize = 1460;

/// L4 read and write buffer sizing.
///
/// Leaving either side as `None` preserves Pingora's default for that side.
/// Setting either side to `Some(0)` disables buffering for that direction:
/// reads and writes then go straight to the socket.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct L4BufferSettings {
    /// Read buffer size in bytes. `None` uses [`DEFAULT_L4_READ_BUFFER_SIZE`].
    pub read: Option<usize>,
    /// Write buffer size in bytes. `None` uses [`DEFAULT_L4_WRITE_BUFFER_SIZE`].
    pub write: Option<usize>,
}

impl L4BufferSettings {
    /// Create settings with both read and write buffer sizes set explicitly.
    pub fn new(read: usize, write: usize) -> Self {
        Self {
            read: Some(read),
            write: Some(write),
        }
    }

    /// Create settings that disable both read and write buffering.
    pub fn unbuffered() -> Self {
        Self::new(0, 0)
    }

    /// Set the read buffer size.
    pub fn read(mut self, read: usize) -> Self {
        self.read = Some(read);
        self
    }

    /// Set the write buffer size.
    pub fn write(mut self, write: usize) -> Self {
        self.write = Some(write);
        self
    }

    /// Resolved read buffer size after applying defaults.
    pub fn read_capacity(&self) -> usize {
        self.read.unwrap_or(DEFAULT_L4_READ_BUFFER_SIZE)
    }

    /// Resolved write buffer size after applying defaults.
    pub fn write_capacity(&self) -> usize {
        self.write.unwrap_or(DEFAULT_L4_WRITE_BUFFER_SIZE)
    }
}

/// The write half of the buffering layer: either straight to the socket or
/// through a [`BufWriter`] with a non-zero capacity.
///
/// Reads always pass straight through to the socket.
#[derive(Debug)]
enum WriteLayer {
    Direct(RawStreamWrapper),
    Buffered(BufWriter<RawStreamWrapper>),
}

impl WriteLayer {
    fn with_capacity(capacity: usize, raw: RawStreamWrapper) -> Self {
        if capacity == 0 {
            WriteLayer::Direct(raw)
        } else {
            WriteLayer::Buffered(BufWriter::with_capacity(capacity, raw))
        }
    }

    fn get_ref(&self) -> &RawStreamWrapper {
        match self {
            WriteLayer::Direct(s) => s,
            WriteLayer::Buffered(s) => s.get_ref(),
        }
    }

    fn get_mut(&mut self) -> &mut RawStreamWrapper {
        match self {
            WriteLayer::Direct(s) => s,
            WriteLayer::Buffered(s) => s.get_mut(),
        }
    }

    /// Resize the write buffer. Bytes still waiting in the current buffer are
    /// never dropped: while any are pending, the current buffer is kept (a
    /// later flush drains it) and the new capacity is not applied.
    fn resize(self, capacity: usize) -> Self {
        match self {
            WriteLayer::Buffered(w) if !w.buffer().is_empty() => WriteLayer::Buffered(w),
            WriteLayer::Buffered(w) => WriteLayer::with_capacity(capacity, w.into_inner()),
            WriteLayer::Direct(raw) => WriteLayer::with_capacity(capacity, raw),
        }
    }
}

impl AsyncRead for WriteLayer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::into_inner(self) {
            WriteLayer::Direct(s) => Pin::new(s).poll_read(cx, buf),
            WriteLayer::Buffered(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WriteLayer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::into_inner(self) {
            WriteLayer::Direct(s) => Pin::new(s).poll_write(cx, buf),
            WriteLayer::Buffered(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match Pin::into_inner(self) {
            WriteLayer::Direct(s) => Pin::new(s).poll_flush(cx),
            WriteLayer::Buffered(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match Pin::into_inner(self) {
            WriteLayer::Direct(s) => Pin::new(s).poll_shutdown(cx),
            WriteLayer::Buffered(s) => Pin::new(s).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match Pin::into_inner(self) {
            WriteLayer::Direct(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            WriteLayer::Buffered(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            WriteLayer::Direct(s) => s.is_write_vectored(),
            WriteLayer::Buffered(s) => s.is_write_vectored(),
        }
    }
}

/// The buffering layer between [`Stream`] and the socket.
///
/// A new stream does no buffering in either direction ([`BufferedIo::direct`]):
/// buffers are only allocated by [`Stream::set_buffer`], off the critical
/// `accept()` path, and until then every read and write goes straight to the
/// socket: a read never pulls more bytes off the socket than it asks for, and a
/// write needs no flush. Accepted streams get their buffers in
/// `UninitializedStream::handshake`, before the pre-TLS callback (PROXY
/// protocol) and the TLS handshake run; those read through this `Stream`, so
/// bytes read ahead into the buffer are not lost. Connector-side streams never
/// call `set_buffer` and stay unbuffered.
///
/// A zero size in [`L4BufferSettings`] means the same pass-through for that
/// direction. Zero is never handed to tokio's buffered types, which reject a
/// zero-capacity read buffer.
#[derive(Debug)]
enum BufferedIo {
    /// Reads go straight to the socket.
    DirectRead(WriteLayer),
    /// Reads go through a [`BufReader`] with a non-zero capacity.
    BufferedRead(BufReader<WriteLayer>),
}

impl BufferedIo {
    /// No buffering in either direction, and no allocation.
    fn direct(raw: RawStreamWrapper) -> Self {
        BufferedIo::DirectRead(WriteLayer::Direct(raw))
    }

    fn get_ref(&self) -> &RawStreamWrapper {
        match self {
            BufferedIo::DirectRead(w) => w.get_ref(),
            BufferedIo::BufferedRead(r) => r.get_ref().get_ref(),
        }
    }

    fn get_mut(&mut self) -> &mut RawStreamWrapper {
        match self {
            BufferedIo::DirectRead(w) => w.get_mut(),
            BufferedIo::BufferedRead(r) => r.get_mut().get_mut(),
        }
    }

    /// Rebuild with new buffer sizes. Returns the rebuilt layer and the bytes
    /// that were read from the socket into the old read buffer but not yet
    /// consumed; the caller must replay them before anything read later.
    fn resize(self, buffer: L4BufferSettings) -> (Self, Vec<u8>) {
        let (write_layer, unread) = match self {
            BufferedIo::DirectRead(w) => (w, Vec::new()),
            BufferedIo::BufferedRead(r) => {
                let unread = r.buffer().to_vec();
                (r.into_inner(), unread)
            }
        };
        let write_layer = write_layer.resize(buffer.write_capacity());
        let read_capacity = buffer.read_capacity();
        let io = if read_capacity == 0 {
            BufferedIo::DirectRead(write_layer)
        } else {
            BufferedIo::BufferedRead(BufReader::with_capacity(read_capacity, write_layer))
        };
        (io, unread)
    }
}

impl AsyncRead for BufferedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::into_inner(self) {
            BufferedIo::DirectRead(s) => Pin::new(s).poll_read(cx, buf),
            BufferedIo::BufferedRead(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for BufferedIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::into_inner(self) {
            BufferedIo::DirectRead(s) => Pin::new(s).poll_write(cx, buf),
            BufferedIo::BufferedRead(s) => Pin::new(s.get_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match Pin::into_inner(self) {
            BufferedIo::DirectRead(s) => Pin::new(s).poll_flush(cx),
            BufferedIo::BufferedRead(s) => Pin::new(s.get_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        match Pin::into_inner(self) {
            BufferedIo::DirectRead(s) => Pin::new(s).poll_shutdown(cx),
            BufferedIo::BufferedRead(s) => Pin::new(s.get_mut()).poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match Pin::into_inner(self) {
            BufferedIo::DirectRead(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            BufferedIo::BufferedRead(s) => Pin::new(s.get_mut()).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            BufferedIo::DirectRead(s) => s.is_write_vectored(),
            BufferedIo::BufferedRead(s) => s.get_ref().is_write_vectored(),
        }
    }
}

// NOTE: with writer buffering, users need to call flush() to make sure the data is actually
// sent. Otherwise data could be stuck in the buffer forever or get lost when stream is closed.

/// A concrete type for transport layer connection + extra fields for logging
#[derive(Debug)]
pub struct Stream {
    // Use `Option` to be able to swap to adjust the buffer size. Always safe to unwrap
    stream: Option<BufferedIo>,
    // the data put back at the front of the read buffer, in order to replay the read
    rewind_read_buf: Vec<Vec<u8>>,
    buffer_write: bool,
    proxy_digest: Option<Arc<ProxyDigest>>,
    socket_digest: Option<Arc<SocketDigest>>,
    /// When this connection is established
    pub established_ts: SystemTime,
    establishment_duration: Option<Duration>,
    offload_wait_duration: Option<Duration>,
    /// The distributed tracing object for this stream
    pub tracer: Option<Tracer>,
    read_pending_time: AccumulatedDuration,
    write_pending_time: AccumulatedDuration,
    /// Last rx timestamp associated with the last recvmsg call.
    pub rx_ts: Option<SystemTime>,
}

impl Stream {
    fn stream(&self) -> &BufferedIo {
        self.stream.as_ref().expect("stream should always be set")
    }

    fn stream_mut(&mut self) -> &mut BufferedIo {
        self.stream.as_mut().expect("stream should always be set")
    }

    /// Record transport connection timing for this stream.
    pub(crate) fn set_establishment_timing(
        &mut self,
        establishment_duration: Duration,
        offload_wait_duration: Option<Duration>,
    ) {
        self.establishment_duration = Some(establishment_duration);
        self.offload_wait_duration = offload_wait_duration;
    }

    /// set TCP nodelay for this connection if `self` is TCP
    pub fn set_nodelay(&mut self) -> Result<()> {
        match &self.stream_mut().get_mut().stream {
            RawStream::Tcp(s) => {
                s.set_nodelay(true)
                    .or_err(ConnectError, "failed to set_nodelay")?;
            }
            RawStream::Virtual(s) => {
                s.set_socket_option(virt::VirtualSockOpt::NoDelay)
                    .or_err(ConnectError, "failed to set_nodelay on virtual socket")?;
            }
            _ => (),
        }
        Ok(())
    }

    /// set TCP keepalive settings for this connection if `self` is TCP
    pub fn set_keepalive(&mut self, ka: &TcpKeepalive) -> Result<()> {
        match &self.stream_mut().get_mut().stream {
            RawStream::Tcp(s) => {
                debug!("Setting tcp keepalive");
                set_tcp_keepalive(s, ka)?;
            }
            RawStream::Virtual(s) => {
                s.set_socket_option(virt::VirtualSockOpt::KeepAlive(ka.clone()))
                    .or_err(ConnectError, "failed to set_keepalive on virtual socket")?;
            }
            _ => (),
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn set_rx_timestamp(&mut self) -> Result<()> {
        use nix::sys::socket::{setsockopt, sockopt, TimestampingFlag};

        if let RawStream::Tcp(s) = &self.stream_mut().get_mut().stream {
            let timestamp_options = TimestampingFlag::SOF_TIMESTAMPING_RX_SOFTWARE
                | TimestampingFlag::SOF_TIMESTAMPING_SOFTWARE;
            setsockopt(&s, sockopt::Timestamping, &timestamp_options)
                .or_err(InternalError, "failed to set SOF_TIMESTAMPING_RX_SOFTWARE")?;
            self.stream_mut().get_mut().enable_rx_ts(true);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn set_rx_timestamp(&mut self) -> io::Result<()> {
        Ok(())
    }

    /// Put some data back to the head of the stream to be read again.
    ///
    /// This is useful when you've read data to detect a protocol (e.g., PROXY protocol)
    /// but the data wasn't what you expected, so you need to "unread" it.
    pub fn rewind(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.rewind_read_buf.push(data.to_vec());
        }
    }

    /// Set the read and write buffer sizes (see [`BufferedIo`]).
    /// It is only set later because of the malloc overhead in critical accept() path
    ///
    /// No data is lost: bytes already in the read buffer are replayed after any
    /// rewound data, and bytes waiting in the write buffer stay there until the
    /// next flush.
    pub(crate) fn set_buffer(&mut self, buffer: L4BufferSettings) {
        let io = self.stream.take().expect("stream should always be set");
        let (io, unread) = io.resize(buffer);
        self.stream = Some(io);
        if !unread.is_empty() {
            // `rewind_read_buf` is read from the back: socket data goes last.
            self.rewind_read_buf.insert(0, unread);
        }
    }
}

impl From<TcpStream> for Stream {
    fn from(s: TcpStream) -> Self {
        Stream {
            stream: Some(BufferedIo::direct(RawStreamWrapper::new(RawStream::Tcp(s)))),
            rewind_read_buf: Vec::new(),
            buffer_write: true,
            established_ts: SystemTime::now(),
            establishment_duration: None,
            offload_wait_duration: None,
            proxy_digest: None,
            socket_digest: None,
            tracer: None,
            read_pending_time: AccumulatedDuration::new(),
            write_pending_time: AccumulatedDuration::new(),
            rx_ts: None,
        }
    }
}

impl From<virt::VirtualSocketStream> for Stream {
    fn from(s: virt::VirtualSocketStream) -> Self {
        Stream {
            stream: Some(BufferedIo::direct(RawStreamWrapper::new(
                RawStream::Virtual(s),
            ))),
            rewind_read_buf: Vec::new(),
            buffer_write: true,
            established_ts: SystemTime::now(),
            establishment_duration: None,
            offload_wait_duration: None,
            proxy_digest: None,
            socket_digest: None,
            tracer: None,
            read_pending_time: AccumulatedDuration::new(),
            write_pending_time: AccumulatedDuration::new(),
            rx_ts: None,
        }
    }
}

#[cfg(unix)]
impl From<UnixStream> for Stream {
    fn from(s: UnixStream) -> Self {
        Stream {
            stream: Some(BufferedIo::direct(RawStreamWrapper::new(RawStream::Unix(
                s,
            )))),
            rewind_read_buf: Vec::new(),
            buffer_write: true,
            established_ts: SystemTime::now(),
            establishment_duration: None,
            offload_wait_duration: None,
            proxy_digest: None,
            socket_digest: None,
            tracer: None,
            read_pending_time: AccumulatedDuration::new(),
            write_pending_time: AccumulatedDuration::new(),
            rx_ts: None,
        }
    }
}

#[cfg(unix)]
impl AsRawFd for Stream {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.stream().get_ref().as_raw_fd()
    }
}

#[cfg(windows)]
impl AsRawSocket for Stream {
    fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
        self.stream().get_ref().as_raw_socket()
    }
}

#[cfg(unix)]
impl UniqueID for Stream {
    fn id(&self) -> UniqueIDType {
        self.as_raw_fd()
    }
}

#[cfg(windows)]
impl UniqueID for Stream {
    fn id(&self) -> usize {
        self.as_raw_socket() as usize
    }
}

impl Ssl for Stream {}

#[async_trait]
impl Peek for Stream {
    async fn try_peek(&mut self, buf: &mut [u8]) -> std::io::Result<bool> {
        use tokio::io::AsyncReadExt;
        self.read_exact(buf).await?;
        // rewind regardless of what is read
        self.rewind(buf);
        Ok(true)
    }
}

#[async_trait]
impl Shutdown for Stream {
    async fn shutdown(&mut self) {
        AsyncWriteExt::shutdown(self).await.unwrap_or_else(|e| {
            debug!("Failed to shutdown connection: {:?}", e);
        });
    }
}

impl GetTimingDigest for Stream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        let mut digest = Vec::with_capacity(2); // expect to have both L4 stream and TLS layer
        digest.push(Some(TimingDigest {
            established_ts: self.established_ts,
            establishment_duration: self.establishment_duration,
            offload_wait_duration: self.offload_wait_duration,
        }));
        digest
    }

    fn get_read_pending_time(&self) -> Duration {
        self.read_pending_time.total
    }

    fn get_write_pending_time(&self) -> Duration {
        self.write_pending_time.total
    }
}

impl GetProxyDigest for Stream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.proxy_digest.clone()
    }

    fn set_proxy_digest(&mut self, digest: ProxyDigest) {
        self.proxy_digest = Some(Arc::new(digest));
    }
}

impl GetSocketDigest for Stream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.socket_digest.clone()
    }

    fn set_socket_digest(&mut self, socket_digest: SocketDigest) {
        self.socket_digest = Some(Arc::new(socket_digest))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if let Some(t) = self.tracer.as_ref() {
            t.0.on_disconnected();
        }
        /* use nodelay/local_addr function to detect socket status */
        let ret = match &self.stream().get_ref().stream {
            RawStream::Tcp(s) => s.nodelay().err(),
            #[cfg(unix)]
            RawStream::Unix(s) => s.local_addr().err(),
            RawStream::Virtual(_) => {
                // TODO: should this do something?
                None
            }
        };
        if let Some(e) = ret {
            match e.kind() {
                tokio::io::ErrorKind::Other => {
                    if let Some(ecode) = e.raw_os_error() {
                        if ecode == 9 {
                            // Or we could panic here
                            error!("Crit: socket {:?} is being double closed", self.stream);
                        }
                    }
                }
                _ => {
                    debug!("Socket is already broken {:?}", e);
                }
            }
        } else {
            // try flush the write buffer. We use now_or_never() because
            // 1. Drop cannot be async
            // 2. write should usually be ready, unless the buf is full.
            let _ = self.flush().now_or_never();
        }
        debug!("Dropping socket {:?}", self.stream);
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = if !self.rewind_read_buf.is_empty() {
            let data_to_read = self.rewind_read_buf.pop().unwrap(); // safe
            let mut data_to_read = data_to_read.as_slice();
            let result = Pin::new(&mut data_to_read).poll_read(cx, buf);
            // return the remaining data back to the head of rewind_read_buf
            if !data_to_read.is_empty() {
                let remaining_buf = Vec::from(data_to_read);
                self.rewind_read_buf.push(remaining_buf);
            }
            result
        } else {
            Pin::new(&mut self.stream_mut()).poll_read(cx, buf)
        };
        self.read_pending_time.poll_time(&result);
        self.rx_ts = self.stream().get_ref().rx_ts;
        result
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = if self.buffer_write {
            Pin::new(&mut self.stream_mut()).poll_write(cx, buf)
        } else {
            Pin::new(&mut self.stream_mut().get_mut()).poll_write(cx, buf)
        };
        self.write_pending_time.poll_write_time(&result, buf.len());
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.stream_mut()).poll_flush(cx);
        self.write_pending_time.poll_time(&result);
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream_mut()).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let total_size = bufs.iter().fold(0, |acc, s| acc + s.len());

        let result = if self.buffer_write {
            Pin::new(&mut self.stream_mut()).poll_write_vectored(cx, bufs)
        } else {
            Pin::new(&mut self.stream_mut().get_mut()).poll_write_vectored(cx, bufs)
        };

        self.write_pending_time.poll_write_time(&result, total_size);
        result
    }

    fn is_write_vectored(&self) -> bool {
        if self.buffer_write {
            // true through a write buffer; the socket's own answer when unbuffered
            self.stream().is_write_vectored()
        } else {
            self.stream().get_ref().is_write_vectored()
        }
    }
}

#[derive(Debug)]
struct AccumulatedDuration {
    total: Duration,
    last_start: Option<Instant>,
}

impl AccumulatedDuration {
    fn new() -> Self {
        AccumulatedDuration {
            total: Duration::ZERO,
            last_start: None,
        }
    }

    fn start(&mut self) {
        if self.last_start.is_none() {
            self.last_start = Some(Instant::now());
        }
    }

    fn stop(&mut self) {
        if let Some(start) = self.last_start.take() {
            self.total += start.elapsed();
        }
    }

    fn poll_write_time(&mut self, result: &Poll<io::Result<usize>>, buf_size: usize) {
        match result {
            Poll::Ready(Ok(n)) => {
                if *n == buf_size {
                    self.stop();
                } else {
                    // partial write
                    self.start();
                }
            }
            Poll::Ready(Err(_)) => {
                self.stop();
            }
            _ => self.start(),
        }
    }

    fn poll_time(&mut self, result: &Poll<io::Result<()>>) {
        match result {
            Poll::Ready(_) => {
                self.stop();
            }
            _ => self.start(),
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::Notify;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_rx_timestamp() {
        let message = "hello world".as_bytes();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let notify = Arc::new(Notify::new());
        let notify2 = notify.clone();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            loop {
                notify2.notified().await;
                stream.write_all(message).await.unwrap();
            }
        });

        let mut stream: Stream = TcpStream::connect(addr).await.unwrap().into();
        stream.set_rx_timestamp().unwrap();
        // The kernel turns on software RX timestamping asynchronously after the
        // setsockopt (a deferred static-key switch), so a packet received right
        // after it may carry no timestamp, more often on a loaded machine. Send
        // messages one at a time until a timestamp shows up, with a bound.
        let mut buffer = vec![0u8; message.len()];
        for _ in 0..100 {
            notify.notify_one();
            stream.read_exact(buffer.as_mut_slice()).await.unwrap();
            assert_eq!(buffer, message);
            if stream.rx_ts.is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no rx timestamp after 100 messages");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_rx_timestamp_standard_path() {
        let message = "hello world".as_bytes();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let notify = Arc::new(Notify::new());
        let notify2 = notify.clone();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            notify2.notified().await;
            stream.write_all(message).await.unwrap();
        });

        let mut stream: Stream = TcpStream::connect(addr).await.unwrap().into();
        std::thread::sleep(Duration::from_micros(100));
        notify.notify_one();

        let mut buffer = vec![0u8; message.len()];
        let n = stream.read(buffer.as_mut_slice()).await.unwrap();
        assert_eq!(n, message.len());
        assert!(stream.rx_ts.is_none());
    }

    #[tokio::test]
    async fn test_stream_rewind() {
        let message = b"hello world";
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let notify = Arc::new(Notify::new());
        let notify2 = notify.clone();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            notify2.notified().await;
            stream.write_all(message).await.unwrap();
        });

        let mut stream: Stream = TcpStream::connect(addr).await.unwrap().into();

        let rewind_test = b"this is Sparta!";
        stream.rewind(rewind_test);

        // partially read rewind_test because of the buffer size limit
        let mut buffer = vec![0u8; message.len()];
        let n = stream.read(buffer.as_mut_slice()).await.unwrap();
        assert_eq!(n, message.len());
        assert_eq!(buffer, rewind_test[..message.len()]);

        // read the rest of rewind_test
        let n = stream.read(buffer.as_mut_slice()).await.unwrap();
        assert_eq!(n, rewind_test.len() - message.len());
        assert_eq!(buffer[..n], rewind_test[message.len()..]);

        // read the actual data
        notify.notify_one();
        let n = stream.read(buffer.as_mut_slice()).await.unwrap();
        assert_eq!(n, message.len());
        assert_eq!(buffer, message);
    }

    #[tokio::test]
    async fn test_stream_peek() {
        let message = b"hello world";
        dbg!("try peek");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let notify = Arc::new(Notify::new());
        let notify2 = notify.clone();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            notify2.notified().await;
            stream.write_all(message).await.unwrap();
            drop(stream);
        });

        notify.notify_one();

        let mut stream: Stream = TcpStream::connect(addr).await.unwrap().into();
        let mut buffer = vec![0u8; 5];
        assert!(stream.try_peek(&mut buffer).await.unwrap());
        assert_eq!(buffer, message[0..5]);
        let mut buffer = vec![];
        stream.read_to_end(&mut buffer).await.unwrap();
        assert_eq!(buffer, message);
    }

    #[tokio::test]
    async fn test_stream_two_subsequent_peek_calls_before_read() {
        let message = b"abcdefghijklmn";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let notify = Arc::new(Notify::new());
        let notify2 = notify.clone();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            notify2.notified().await;
            stream.write_all(message).await.unwrap();
            drop(stream);
        });

        notify.notify_one();

        let mut stream: Stream = TcpStream::connect(addr).await.unwrap().into();

        // Peek 4 bytes
        let mut buffer = vec![0u8; 4];
        assert!(stream.try_peek(&mut buffer).await.unwrap());
        assert_eq!(buffer, message[0..4]);

        // Peek 2 bytes
        let mut buffer = vec![0u8; 2];
        assert!(stream.try_peek(&mut buffer).await.unwrap());
        assert_eq!(buffer, message[0..2]);

        // Read 1 byte: ['a']
        let mut buffer = vec![0u8; 1];
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(buffer, message[0..1]);

        // Read as many bytes as possible, return 1 byte ['b']
        //  from the first retry buffer chunk
        let mut buffer = vec![0u8; 100];
        let n = stream.read(&mut buffer).await.unwrap();
        assert_eq!(n, 1);
        assert_eq!(buffer[..n], message[1..2]);

        // Read the rest ['cdefghijklmn']
        let mut buffer = vec![];
        stream.read_to_end(&mut buffer).await.unwrap();
        assert_eq!(buffer, message[2..]);
    }

    /// A connected pair: the `Stream` under test and the raw peer socket.
    fn unix_pair() -> (Stream, UnixStream) {
        let (ours, peer) = UnixStream::pair().unwrap();
        (Stream::from(ours), peer)
    }

    /// Read exactly `n` bytes from `peer`, failing if they don't arrive promptly.
    async fn peer_read(peer: &mut UnixStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(Duration::from_secs(5), peer.read_exact(&mut buf))
            .await
            .expect("peer did not receive the bytes")
            .unwrap();
        buf
    }

    /// Assert that nothing reaches `peer` within a short window.
    async fn peer_receives_nothing(peer: &mut UnixStream) {
        let mut buf = [0u8; 1];
        let res = tokio::time::timeout(Duration::from_millis(100), peer.read(&mut buf)).await;
        assert!(res.is_err(), "peer unexpectedly received {res:?}");
    }

    // Before `set_buffer`, a stream does no buffering at all: it allocates no
    // buffers on the accept path, and every write reaches the socket without a
    // flush.
    #[tokio::test]
    async fn test_new_stream_writes_through_without_flush() {
        let (mut stream, mut peer) = unix_pair();
        stream.write_all(b"x").await.unwrap();
        assert_eq!(peer_read(&mut peer, 1).await, b"x");

        let bufs = [std::io::IoSlice::new(b"ab"), std::io::IoSlice::new(b"cd")];
        let n = stream.write_vectored(&bufs).await.unwrap();
        assert!(n > 0);
        assert_eq!(peer_read(&mut peer, n).await, b"abcd"[..n]);
    }

    // Before `set_buffer`, reads go straight to the socket and never read
    // ahead: a pre-TLS consumer (PROXY protocol, `peek`) takes exactly what it
    // asks for, and the rest is still in the socket when the buffers are set.
    #[tokio::test]
    async fn test_new_stream_reads_do_not_read_ahead() {
        let (mut stream, mut peer) = unix_pair();
        peer.write_all(b"hello world").await.unwrap();

        let mut one = [0u8; 1];
        stream.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"h");

        // Nothing was buffered inside `stream`: the raw socket still holds the rest.
        let mut rest = [0u8; 10];
        let raw = match &mut stream.stream_mut().get_mut().stream {
            RawStream::Unix(s) => s,
            other => panic!("unexpected raw stream {other:?}"),
        };
        raw.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"ello world");
    }

    #[tokio::test]
    async fn test_set_buffer_unbuffered_writes_through() {
        let (mut stream, mut peer) = unix_pair();
        stream.set_buffer(L4BufferSettings::unbuffered());
        stream.write_all(b"x").await.unwrap();
        assert_eq!(peer_read(&mut peer, 1).await, b"x");

        peer.write_all(b"pong").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn test_set_buffer_default_holds_writes_until_flush() {
        let (mut stream, mut peer) = unix_pair();
        stream.set_buffer(L4BufferSettings::default());
        stream.write_all(b"x").await.unwrap();
        peer_receives_nothing(&mut peer).await;
        stream.flush().await.unwrap();
        assert_eq!(peer_read(&mut peer, 1).await, b"x");

        // A write at least as large as the write buffer bypasses it.
        let big = vec![7u8; DEFAULT_L4_WRITE_BUFFER_SIZE];
        stream.write_all(&big).await.unwrap();
        assert_eq!(peer_read(&mut peer, big.len()).await, big);
    }

    // A zero read buffer with a non-zero write buffer: reads are direct, writes
    // are buffered.
    #[tokio::test]
    async fn test_set_buffer_zero_read_buffered_write() {
        let (mut stream, mut peer) = unix_pair();
        stream.set_buffer(L4BufferSettings::default().read(0));

        peer.write_all(b"hello").await.unwrap();
        let mut one = [0u8; 1];
        stream.read_exact(&mut one).await.unwrap();
        let mut rest = [0u8; 4];
        let raw = match &mut stream.stream_mut().get_mut().stream {
            RawStream::Unix(s) => s,
            other => panic!("unexpected raw stream {other:?}"),
        };
        raw.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"ello");

        stream.write_all(b"x").await.unwrap();
        peer_receives_nothing(&mut peer).await;
        stream.flush().await.unwrap();
        assert_eq!(peer_read(&mut peer, 1).await, b"x");
    }

    // A zero write buffer with a non-zero read buffer: writes go through.
    #[tokio::test]
    async fn test_set_buffer_buffered_read_zero_write() {
        let (mut stream, mut peer) = unix_pair();
        stream.set_buffer(L4BufferSettings::default().write(0));
        stream.write_all(b"x").await.unwrap();
        assert_eq!(peer_read(&mut peer, 1).await, b"x");

        peer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    // Bytes already pulled into the read buffer survive a later `set_buffer`,
    // after any rewound data and in order.
    #[tokio::test]
    async fn test_set_buffer_keeps_buffered_read_data() {
        let (mut stream, mut peer) = unix_pair();
        stream.set_buffer(L4BufferSettings::default());
        peer.write_all(b"hello world").await.unwrap();
        drop(peer);

        let mut one = [0u8; 1];
        stream.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"h");
        stream.rewind(b"H");

        stream.set_buffer(L4BufferSettings::unbuffered());
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"Hello world");
    }

    // Bytes waiting in the write buffer survive a later `set_buffer`.
    #[tokio::test]
    async fn test_set_buffer_keeps_pending_write_data() {
        let (mut stream, mut peer) = unix_pair();
        stream.set_buffer(L4BufferSettings::default());
        stream.write_all(b"x").await.unwrap();
        stream.set_buffer(L4BufferSettings::new(1024, 4096));
        stream.flush().await.unwrap();
        assert_eq!(peer_read(&mut peer, 1).await, b"x");
    }

    #[tokio::test]
    async fn test_peek_and_rewind_with_buffers() {
        for settings in [
            L4BufferSettings::default(),
            L4BufferSettings::unbuffered(),
            L4BufferSettings::default().read(0),
        ] {
            let (mut stream, mut peer) = unix_pair();
            stream.set_buffer(settings);
            peer.write_all(b"abcdef").await.unwrap();
            drop(peer);

            let mut peeked = [0u8; 3];
            assert!(stream.try_peek(&mut peeked).await.unwrap());
            assert_eq!(&peeked, b"abc", "{settings:?}");
            stream.rewind(b"XY");

            let mut all = Vec::new();
            stream.read_to_end(&mut all).await.unwrap();
            assert_eq!(all, b"XYabcdef", "{settings:?}");
        }
    }

    // Dropping a stream makes a best-effort flush of its write buffer.
    #[tokio::test]
    async fn test_drop_flushes_write_buffer() {
        let (mut stream, mut peer) = unix_pair();
        stream.set_buffer(L4BufferSettings::default());
        stream.write_all(b"bye").await.unwrap();
        drop(stream);
        let mut all = Vec::new();
        peer.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"bye");
    }

    #[tokio::test]
    async fn test_tcp_stream_set_buffer_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
        });

        let mut stream: Stream = TcpStream::connect(addr).await.unwrap().into();
        stream.set_buffer(L4BufferSettings::default());
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        echo.await.unwrap();
    }
}
