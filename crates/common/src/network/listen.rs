/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ServerInstance, SessionData, SessionManager, SessionStream, TcpAcceptor,
    limiter::{ConcurrencyLimiter, LimiterResult},
};
use crate::{
    BuildServer, Inner, Server,
    config::server::{Listener, Listeners, ServerProtocol, TcpListener},
};
use compact_str::{ToCompactString, format_compact};
use proxy_header::io::ProxiedStream;
use registry::types::id::ObjectId;
use rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256;
use socket2::{SockRef, TcpKeepalive};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use store::registry::bootstrap::Bootstrap;
use tokio::{
    net::{TcpStream, UnixListener},
    sync::watch,
    time::timeout,
};
use tokio_rustls::server::TlsStream;
use trc::{EventType, HttpEvent, ImapEvent, ManageSieveEvent, Pop3Event, SmtpEvent};
use utils::UnwrapFailure;

impl Listener {
    pub fn spawn(
        self,
        manager: impl SessionManager,
        inner: Arc<Inner>,
        acceptor: TcpAcceptor,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        // Prepare instance
        let instance = Arc::new(ServerInstance {
            id: self.id,
            protocol: self.protocol,
            unix_socket: self.unix_socket.is_some(),
            admin: self.admin,
            proxy_networks: self.proxy_networks,
            limiter: ConcurrencyLimiter::new(self.max_connections),
            tls_timeout: self.tls_timeout,
            acceptor,
            shutdown_rx,
            span_id_gen: self.span_id_gen,
        });
        let is_tls = matches!(instance.acceptor, TcpAcceptor::Tls { implicit, .. } if implicit);
        let is_https = is_tls && self.protocol == ServerProtocol::Http;
        let has_proxies = !instance.proxy_networks.is_empty();

        if let Some((path, local_addr)) = self.unix_socket {
            spawn_unix(path, local_addr, instance, manager, inner);
            return;
        }

        // Spawn listeners
        for listener in self.listeners {
            let local_addr = listener.addr;

            // Obtain TCP options
            let opts = SocketOpts {
                nodelay: listener.nodelay,
                ttl: listener.ttl,
            };

            // Bind socket
            let listener = match listener.listen() {
                Ok(listener) => {
                    trc::event!(
                        Network(trc::NetworkEvent::ListenStart),
                        ListenerId = instance.id.clone(),
                        LocalIp = local_addr.ip(),
                        LocalPort = local_addr.port(),
                        Tls = is_tls,
                    );

                    listener
                }
                Err(err) => {
                    trc::event!(
                        Network(trc::NetworkEvent::ListenError),
                        ListenerId = instance.id.clone(),
                        LocalIp = local_addr.ip(),
                        LocalPort = local_addr.port(),
                        Tls = is_tls,
                        Reason = err,
                    );

                    continue;
                }
            };

            // Spawn listener
            let mut shutdown_rx = instance.shutdown_rx.clone();
            let manager = manager.clone();
            let instance = instance.clone();
            let inner = inner.clone();
            tokio::spawn(async move {
                let (span_start, span_end) = span_events(self.protocol);

                const ACCEPT_BACKOFF: Duration = Duration::from_millis(5);
                const MAX_ACCEPT_BACKOFF: Duration = Duration::from_secs(1);
                let mut accept_backoff = ACCEPT_BACKOFF;

                loop {
                    tokio::select! {
                        stream = listener.accept() => {
                            match stream {
                                Ok((stream, remote_addr)) => {
                                    accept_backoff = ACCEPT_BACKOFF;

                                    let server = inner.build_server();
                                    let enable_acme = (is_https && server.has_acme_tls_providers()).then(|| server.clone());

                                    if has_proxies && instance.proxy_networks.iter().any(|network| network.matches(&remote_addr.ip())) {
                                        let instance = instance.clone();
                                        let manager = manager.clone();

                                        // Set socket options
                                        opts.apply(&stream);

                                        tokio::spawn(async move {
                                            match timeout(instance.tls_timeout, ProxiedStream::create_from_tokio(stream, Default::default())).await {
                                                Ok(Ok(stream)) =>{
                                                    let (remote_addr, local_addr) = stream.proxy_header()
                                                                            .proxied_address()
                                                                            .map(|addr| {
                                                                                let local_addr = match addr.destination.ip() {
                                                                                    IpAddr::V6(ip) => ip
                                                                                        .to_ipv4_mapped()
                                                                                        .map(|ip| SocketAddr::new(IpAddr::V4(ip), addr.destination.port()))
                                                                                        .unwrap_or(addr.destination),
                                                                                    _ => addr.destination,
                                                                                };

                                                                                (addr.source, local_addr)
                                                                            })
                                                                            .unwrap_or((remote_addr, local_addr));
                                                    if let Some(session) = instance.build_session(stream, local_addr, remote_addr, &server) {
                                                        // Spawn session
                                                        manager.spawn(session, is_tls, enable_acme, span_start, span_end);
                                                    }
                                                }
                                                Err(_) => {
                                                    trc::event!(
                                                        Network(trc::NetworkEvent::Timeout),
                                                        ListenerId = instance.id.clone(),
                                                        LocalIp = local_addr.ip(),
                                                        LocalPort = local_addr.port(),
                                                        RemoteIp = remote_addr.ip(),
                                                        Tls = is_tls,
                                                        Reason = "PROXY protocol header timeout",
                                                    );
                                                }
                                                Ok(Err(err)) => {
                                                    trc::event!(
                                                        Network(trc::NetworkEvent::ProxyError),
                                                        ListenerId = instance.id.clone(),
                                                        LocalIp = local_addr.ip(),
                                                        LocalPort = local_addr.port(),
                                                        RemoteIp = remote_addr.ip(),
                                                        RemotePort = remote_addr.port(),
                                                        Tls = is_tls,
                                                        Reason = err.to_compact_string(),
                                                    );
                                                }
                                            }
                                        });
                                    } else if let Some(session) = instance.build_session(stream, local_addr, remote_addr, &server) {
                                        // Set socket options
                                        opts.apply(&session.stream);

                                        // Spawn session
                                        manager.spawn(session, is_tls, enable_acme, span_start, span_end);
                                    }
                                }
                                Err(err) => {
                                    if matches!(
                                        err.kind(),
                                        std::io::ErrorKind::ConnectionAborted
                                            | std::io::ErrorKind::ConnectionReset
                                            | std::io::ErrorKind::Interrupted
                                    ) {
                                        continue;
                                    }

                                    trc::event!(
                                        Network(trc::NetworkEvent::AcceptError),
                                        ListenerId = instance.id.clone(),
                                        LocalIp = local_addr.ip(),
                                        LocalPort = local_addr.port(),
                                        Tls = is_tls,
                                        Reason = err.to_compact_string(),
                                    );

                                    tokio::select! {
                                        _ = tokio::time::sleep(accept_backoff) => {}
                                        _ = shutdown_rx.changed() => {
                                            manager.shutdown().await;
                                            break;
                                        }
                                    }

                                    accept_backoff = (accept_backoff * 2).min(MAX_ACCEPT_BACKOFF);
                                }
                            }
                        },
                        _ = shutdown_rx.changed() => {

                            trc::event!(
                                Network(trc::NetworkEvent::ListenStop),
                                ListenerId = instance.id.clone(),
                                LocalIp = local_addr.ip(),
                                Tls = is_tls,
                                LocalPort = local_addr.port(),
                            );

                            manager.shutdown().await;
                            break;
                        }
                    };
                }
            });
        }
    }
}

fn span_events(protocol: ServerProtocol) -> (EventType, EventType) {
    match protocol {
        ServerProtocol::Smtp | ServerProtocol::Lmtp => (
            EventType::Smtp(SmtpEvent::ConnectionStart),
            EventType::Smtp(SmtpEvent::ConnectionEnd),
        ),
        ServerProtocol::Imap => (
            EventType::Imap(ImapEvent::ConnectionStart),
            EventType::Imap(ImapEvent::ConnectionEnd),
        ),
        ServerProtocol::Pop3 => (
            EventType::Pop3(Pop3Event::ConnectionStart),
            EventType::Pop3(Pop3Event::ConnectionEnd),
        ),
        ServerProtocol::Http => (
            EventType::Http(HttpEvent::ConnectionStart),
            EventType::Http(HttpEvent::ConnectionEnd),
        ),
        ServerProtocol::ManageSieve => (
            EventType::ManageSieve(ManageSieveEvent::ConnectionStart),
            EventType::ManageSieve(ManageSieveEvent::ConnectionEnd),
        ),
    }
}

fn spawn_unix(
    path: PathBuf,
    local_addr: SocketAddr,
    instance: Arc<ServerInstance>,
    manager: impl SessionManager,
    inner: Arc<Inner>,
) {
    let (span_start, span_end) = span_events(instance.protocol);

    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(err) => {
            trc::event!(
                Network(trc::NetworkEvent::ListenError),
                ListenerId = instance.id.clone(),
                Details = path.to_string_lossy().to_compact_string(),
                Reason = err.to_compact_string(),
            );
            return;
        }
    };
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));

    trc::event!(
        Network(trc::NetworkEvent::ListenStart),
        ListenerId = instance.id.clone(),
        Details = path.to_string_lossy().to_compact_string(),
    );

    let mut shutdown_rx = instance.shutdown_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                stream = listener.accept() => {
                    match stream {
                        Ok((stream, _)) => {
                            let server = inner.build_server();
                            if let Some(session) = instance.build_session(stream, local_addr, local_addr, &server) {
                                manager.spawn(session, false, None, span_start, span_end);
                            }
                        }
                        Err(err) => {
                            trc::event!(
                                Network(trc::NetworkEvent::AcceptError),
                                ListenerId = instance.id.clone(),
                                Reason = err.to_compact_string(),
                            );
                            tokio::select! {
                                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
                                _ = shutdown_rx.changed() => {
                                    manager.shutdown().await;
                                    break;
                                }
                            }
                        }
                    }
                },
                _ = shutdown_rx.changed() => {
                    trc::event!(
                        Network(trc::NetworkEvent::ListenStop),
                        ListenerId = instance.id.clone(),
                        Details = path.to_string_lossy().to_compact_string(),
                    );
                    manager.shutdown().await;
                    let _ = std::fs::remove_file(&path);
                    break;
                }
            }
        }
    });
}

trait BuildSession {
    fn build_session<T: SessionStream>(
        &self,
        stream: T,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        server: &Server,
    ) -> Option<SessionData<T>>;
}

impl BuildSession for Arc<ServerInstance> {
    fn build_session<T: SessionStream>(
        &self,
        stream: T,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        server: &Server,
    ) -> Option<SessionData<T>> {
        // Convert mapped IPv6 addresses to IPv4
        let remote_ip = match remote_addr.ip() {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            remote_ip => remote_ip,
        };
        let remote_port = remote_addr.port();

        // Check if blocked
        if server.is_ip_blocked(remote_ip) {
            trc::event!(
                Security(trc::SecurityEvent::IpBlocked),
                ListenerId = self.id.clone(),
                LocalPort = local_addr.port(),
                RemoteIp = remote_ip,
                RemotePort = remote_port,
            );
            None
        } else if let LimiterResult::Allowed(in_flight) = self.limiter.is_allowed() {
            // Enforce concurrency
            SessionData {
                stream,
                in_flight,
                local_ip: local_addr.ip(),
                local_port: local_addr.port(),
                session_id: 0,
                remote_ip,
                remote_port,
                protocol: self.protocol,
                instance: self.clone(),
            }
            .into()
        } else {
            trc::event!(
                Limit(trc::LimitEvent::ConcurrentConnection),
                ListenerId = self.id.clone(),
                LocalPort = local_addr.port(),
                RemoteIp = remote_ip,
                RemotePort = remote_port,
                Limit = self.limiter.max_concurrent(),
            );

            None
        }
    }
}

pub struct SocketOpts {
    pub nodelay: bool,
    pub ttl: Option<u32>,
}

const KEEPALIVE_IDLE: Duration = Duration::from_secs(300);
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
))]
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
const KEEPALIVE_RETRIES: u32 = 4;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
const KEEPALIVE: TcpKeepalive = TcpKeepalive::new()
    .with_time(KEEPALIVE_IDLE)
    .with_interval(KEEPALIVE_INTERVAL)
    .with_retries(KEEPALIVE_RETRIES);
#[cfg(windows)]
const KEEPALIVE: TcpKeepalive = TcpKeepalive::new()
    .with_time(KEEPALIVE_IDLE)
    .with_interval(KEEPALIVE_INTERVAL);
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
const KEEPALIVE: TcpKeepalive = TcpKeepalive::new().with_time(KEEPALIVE_IDLE);

impl SocketOpts {
    pub fn apply(&self, stream: &TcpStream) {
        // Set TCP options
        if let Err(err) = stream.set_nodelay(self.nodelay) {
            trc::event!(
                Network(trc::NetworkEvent::SetOptError),
                Reason = err.to_compact_string(),
                Details = "Failed to set TCP_NODELAY",
            );
        }
        if let Err(err) = SockRef::from(stream).set_tcp_keepalive(&KEEPALIVE) {
            trc::event!(
                Network(trc::NetworkEvent::SetOptError),
                Reason = err.to_compact_string(),
                Details = "Failed to set TCP keepalive",
            );
        }
        if let Some(ttl) = self.ttl
            && let Err(err) = stream.set_ttl(ttl)
        {
            trc::event!(
                Network(trc::NetworkEvent::SetOptError),
                Reason = err.to_compact_string(),
                Details = "Failed to set TTL",
            );
        }
    }
}

impl Listeners {
    pub fn bind_and_drop_priv(&mut self, bp: &mut Bootstrap) {
        // Bind as root
        self.bind(|registry_id, addr, err| {
            bp.build_error(registry_id, format!("Failed to bind to {addr}: {err}"));
        });

        // Drop privileges
        #[cfg(not(target_env = "msvc"))]
        {
            if let Ok(run_as_user) = std::env::var("RUN_AS_USER") {
                let mut pd = privdrop::PrivDrop::default()
                    .user(run_as_user)
                    .fallback_to_ids_if_names_are_numeric();
                if let Ok(run_as_group) = std::env::var("RUN_AS_GROUP") {
                    pd = pd
                        .group(run_as_group)
                        .fallback_to_ids_if_names_are_numeric();
                }
                pd.apply().failed("Failed to drop privileges");
            }
        }
    }

    fn bind(&mut self, mut on_error: impl FnMut(ObjectId, SocketAddr, io::Error)) {
        for server in &mut self.servers {
            let registry_id = server.registry_id;
            let server_id = &server.id;
            server
                .listeners
                .retain(|listener| match listener.socket.bind(listener.addr) {
                    Ok(()) => true,
                    Err(err) => {
                        trc::event!(
                            Network(trc::NetworkEvent::ListenError),
                            ListenerId = server_id.clone(),
                            LocalIp = listener.addr.ip(),
                            LocalPort = listener.addr.port(),
                            Reason = err.to_compact_string(),
                        );
                        on_error(registry_id, listener.addr, err);
                        false
                    }
                });
        }
        self.servers
            .retain(|server| !server.listeners.is_empty() || server.unix_socket.is_some());
    }

    pub fn spawn(
        mut self,
        spawn: impl Fn(Listener, TcpAcceptor, watch::Receiver<bool>),
    ) -> (watch::Sender<bool>, watch::Receiver<bool>) {
        // Spawn listeners
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        for server in self.servers {
            let acceptor = self
                .tcp_acceptors
                .remove(&server.id)
                .unwrap_or(TcpAcceptor::Plain);

            spawn(server, acceptor, shutdown_rx.clone());
        }
        (shutdown_tx, shutdown_rx)
    }
}

impl TcpListener {
    pub fn listen(self) -> Result<tokio::net::TcpListener, String> {
        match self.socket.local_addr() {
            Ok(local_addr) if self.is_bound_to(local_addr) => self
                .socket
                .listen(self.backlog.unwrap_or(1024))
                .map_err(|err| format!("Failed to listen on {}: {}", self.addr, err)),
            Ok(local_addr) => Err(format!(
                "Refusing to listen on {}: socket is bound to {local_addr}",
                self.addr
            )),
            Err(err) => Err(format!(
                "Refusing to listen on {}: socket is not bound: {err}",
                self.addr
            )),
        }
    }

    fn is_bound_to(&self, local_addr: SocketAddr) -> bool {
        local_addr.ip() == self.addr.ip()
            && local_addr.port() != 0
            && (self.addr.port() == 0 || local_addr.port() == self.addr.port())
    }
}

impl ServerInstance {
    pub async fn tls_accept<T: SessionStream>(
        &self,
        stream: T,
        session_id: u64,
    ) -> Result<TlsStream<T>, ()> {
        match &self.acceptor {
            TcpAcceptor::Tls { acceptor, .. } => {
                match timeout(self.tls_timeout, acceptor.accept(stream))
                    .await
                    .unwrap_or_else(|_| Err(io::Error::from(io::ErrorKind::TimedOut)))
                {
                    Ok(stream) => {
                        trc::event!(
                            Tls(trc::TlsEvent::Handshake),
                            ListenerId = self.id.clone(),
                            SpanId = session_id,
                            Version = format_compact!(
                                "{:?}",
                                stream
                                    .get_ref()
                                    .1
                                    .protocol_version()
                                    .unwrap_or(rustls::ProtocolVersion::TLSv1_3)
                            ),
                            Cipher = format_compact!(
                                "{:?}",
                                stream
                                    .get_ref()
                                    .1
                                    .negotiated_cipher_suite()
                                    .unwrap_or(TLS13_AES_128_GCM_SHA256)
                            )
                        );
                        Ok(stream)
                    }
                    Err(err) => {
                        trc::event!(
                            Tls(trc::TlsEvent::HandshakeError),
                            ListenerId = self.id.clone(),
                            SpanId = session_id,
                            Reason = err.to_compact_string(),
                        );
                        Err(())
                    }
                }
            }
            TcpAcceptor::Plain => {
                trc::event!(
                    Tls(trc::TlsEvent::NotConfigured),
                    ListenerId = self.id.clone(),
                    SpanId = session_id,
                );
                Err(())
            }
        }
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/common/src/network/listen/tests.rs"]
mod tests;
