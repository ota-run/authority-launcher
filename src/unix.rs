// Copyright (C) 2026 — 2026, Ota. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0. See LICENSE for the full license text.
// You may not use this file except in compliance with that License.

use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::config::{CoreBindingSelection, LauncherConfig, SessionPeer};

#[derive(Debug, Error)]
pub(crate) enum LauncherError {
    #[error("the protected broker session descriptor is unavailable")]
    MissingBrokerSession,
    #[error("the protected broker session is not a connected Unix stream")]
    InvalidBrokerSession,
    #[error("the protected broker session peer does not match administrator-owned configuration")]
    BrokerPeerMismatch,
    #[error("the Ota launcher session could not be created")]
    SessionCreation,
    #[error("the protected Ota process could not be started")]
    ProcessStart,
    #[error("the protected Ota process could not be observed")]
    ProcessWait,
    #[error("the launcher session bridge failed")]
    SessionBridge,
    #[error(
        "the authority launcher must start as root before dropping to the configured principal"
    )]
    RootRequired,
}

pub(crate) fn launch(
    config: LauncherConfig,
    broker_session_descriptor: RawFd,
    expected_peer: SessionPeer,
    core_binding: CoreBindingSelection,
    ota_args: &[String],
) -> Result<u8, LauncherError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(LauncherError::RootRequired);
    }
    launch_inner(
        config,
        broker_session_descriptor,
        expected_peer,
        core_binding,
        ota_args,
    )
}

fn launch_inner(
    config: LauncherConfig,
    broker_session_descriptor: RawFd,
    expected_peer: SessionPeer,
    core_binding: CoreBindingSelection,
    ota_args: &[String],
) -> Result<u8, LauncherError> {
    if broker_session_descriptor == core_binding.ota_session_descriptor {
        return Err(LauncherError::InvalidBrokerSession);
    }
    let broker = take_connected_unix_stream(broker_session_descriptor, expected_peer)?;
    let (launcher, ota) = UnixStream::pair().map_err(|_| LauncherError::SessionCreation)?;
    set_cloexec(launcher.as_raw_fd(), true).map_err(|_| LauncherError::SessionCreation)?;
    set_cloexec(ota.as_raw_fd(), true).map_err(|_| LauncherError::SessionCreation)?;

    let ota_fd = ota.as_raw_fd();
    let target_fd = core_binding.ota_session_descriptor;
    let run_uid = config.run_as.uid;
    let run_gid = config.run_as.gid;
    let launcher_pid = unsafe { libc::getpid() };
    let mut command = Command::new(config.ota_binary);
    command
        .args(ota_args)
        .env_clear()
        .envs(config.environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // SAFETY: every operation is async-signal-safe and runs after fork before exec. The closure
    // does not allocate or access shared synchronization state.
    unsafe {
        command.pre_exec(move || prepare_child(ota_fd, target_fd, run_uid, run_gid, launcher_pid));
    }
    let mut child = command.spawn().map_err(|_| LauncherError::ProcessStart)?;
    drop(ota);

    let bridge = match start_bridge(&launcher, &broker) {
        Ok(bridge) => bridge,
        Err(error) => {
            terminate_and_reap(&mut child);
            return Err(error);
        }
    };
    let status = supervise(&mut child, &bridge);
    bridge.stopping.store(true, Ordering::Release);
    let _ = launcher.shutdown(Shutdown::Both);
    let _ = broker.shutdown(Shutdown::Both);
    finish_bridge(bridge)?;
    Ok(exit_code(status?))
}

type BridgeHandle = JoinHandle<io::Result<()>>;

struct Bridge {
    upstream: BridgeHandle,
    downstream: BridgeHandle,
    stopping: Arc<AtomicBool>,
    events: Receiver<io::Result<()>>,
}

fn start_bridge(ota: &UnixStream, broker: &UnixStream) -> Result<Bridge, LauncherError> {
    let ota_reader = ota.try_clone().map_err(|_| LauncherError::SessionBridge)?;
    let ota_writer = ota.try_clone().map_err(|_| LauncherError::SessionBridge)?;
    let broker_reader = broker
        .try_clone()
        .map_err(|_| LauncherError::SessionBridge)?;
    let broker_writer = broker
        .try_clone()
        .map_err(|_| LauncherError::SessionBridge)?;
    let stopping = Arc::new(AtomicBool::new(false));
    let (event_sender, events) = mpsc::channel();
    let upstream_stopping = Arc::clone(&stopping);
    let downstream_stopping = Arc::clone(&stopping);
    let upstream_events = event_sender.clone();
    let upstream = thread::spawn(move || {
        let result = copy_and_shutdown(ota_reader, broker_writer, upstream_stopping.as_ref());
        let _ = upstream_events.send(result.as_ref().map(|_| ()).map_err(clone_io_error));
        result
    });
    let downstream = thread::spawn(move || {
        let result = copy_and_shutdown(broker_reader, ota_writer, downstream_stopping.as_ref());
        let _ = event_sender.send(result.as_ref().map(|_| ()).map_err(clone_io_error));
        result
    });
    Ok(Bridge {
        upstream,
        downstream,
        stopping,
        events,
    })
}

fn clone_io_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}

fn supervise(
    child: &mut std::process::Child,
    bridge: &Bridge,
) -> Result<ExitStatus, LauncherError> {
    let mut events_closed = false;
    loop {
        if let Some(status) = child.try_wait().map_err(|_| LauncherError::ProcessWait)? {
            return Ok(status);
        }
        if events_closed {
            thread::sleep(Duration::from_millis(10));
            continue;
        }
        match bridge.events.recv_timeout(Duration::from_millis(10)) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                terminate_and_reap(child);
                return Err(LauncherError::SessionBridge);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => events_closed = true,
        }
    }
}

fn terminate_and_reap(child: &mut std::process::Child) {
    let pid = child.id() as libc::pid_t;
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn finish_bridge(bridge: Bridge) -> Result<(), LauncherError> {
    bridge
        .upstream
        .join()
        .map_err(|_| LauncherError::SessionBridge)?
        .map_err(|_| LauncherError::SessionBridge)?;
    bridge
        .downstream
        .join()
        .map_err(|_| LauncherError::SessionBridge)?
        .map_err(|_| LauncherError::SessionBridge)?;
    Ok(())
}

fn copy_and_shutdown(
    mut reader: UnixStream,
    mut writer: UnixStream,
    stopping: &AtomicBool,
) -> io::Result<()> {
    if let Err(error) = io::copy(&mut reader, &mut writer)
        && !stopping.load(Ordering::Acquire)
    {
        return Err(error);
    }
    if let Err(error) = writer.shutdown(Shutdown::Write)
        && !stopping.load(Ordering::Acquire)
    {
        return Err(error);
    }
    Ok(())
}

fn take_connected_unix_stream(
    descriptor: RawFd,
    expected_peer: SessionPeer,
) -> Result<UnixStream, LauncherError> {
    if descriptor < 3 {
        return Err(LauncherError::MissingBrokerSession);
    }
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(LauncherError::MissingBrokerSession);
    }
    reject_standard_stream_alias(descriptor)?;
    verify_connected_unix_stream(descriptor)?;
    verify_peer_identity(descriptor, expected_peer)?;
    set_cloexec(descriptor, true).map_err(|_| LauncherError::InvalidBrokerSession)?;
    // SAFETY: F_GETFD proved this descriptor is open, and the launcher now takes sole ownership.
    Ok(unsafe { UnixStream::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn verify_peer_identity(descriptor: RawFd, expected: SessionPeer) -> Result<(), LauncherError> {
    let mut observed: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut observed as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if result != 0 || observed.uid != expected.uid || observed.gid != expected.gid {
        return Err(LauncherError::BrokerPeerMismatch);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_peer_identity(descriptor: RawFd, expected: SessionPeer) -> Result<(), LauncherError> {
    let mut uid = 0_u32;
    let mut gid = 0_u32;
    let result = unsafe { libc::getpeereid(descriptor, &mut uid, &mut gid) };
    if result != 0 || uid != expected.uid || gid != expected.gid {
        return Err(LauncherError::BrokerPeerMismatch);
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn verify_peer_identity(_descriptor: RawFd, _expected: SessionPeer) -> Result<(), LauncherError> {
    Err(LauncherError::BrokerPeerMismatch)
}

fn reject_standard_stream_alias(descriptor: RawFd) -> Result<(), LauncherError> {
    let mut source: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(descriptor, &mut source) } != 0 {
        return Err(LauncherError::InvalidBrokerSession);
    }
    for standard in 0..=2 {
        let mut candidate: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(standard, &mut candidate) } == 0
            && source.st_dev == candidate.st_dev
            && source.st_ino == candidate.st_ino
        {
            return Err(LauncherError::InvalidBrokerSession);
        }
    }
    Ok(())
}

fn verify_connected_unix_stream(descriptor: RawFd) -> Result<(), LauncherError> {
    let mut socket_type = 0_i32;
    let mut socket_type_len = std::mem::size_of::<i32>() as libc::socklen_t;
    let socket_result = unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut socket_type_len,
        )
    };
    if socket_result != 0 || socket_type != libc::SOCK_STREAM {
        return Err(LauncherError::InvalidBrokerSession);
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut address_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let peer_result = unsafe {
        libc::getpeername(
            descriptor,
            (&mut address as *mut libc::sockaddr_un).cast(),
            &mut address_len,
        )
    };
    if peer_result != 0 || address.sun_family as i32 != libc::AF_UNIX {
        return Err(LauncherError::InvalidBrokerSession);
    }
    let mut local: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut local_len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let local_result = unsafe {
        libc::getsockname(
            descriptor,
            (&mut local as *mut libc::sockaddr_un).cast(),
            &mut local_len,
        )
    };
    if local_result != 0 || local.sun_family as i32 != libc::AF_UNIX {
        return Err(LauncherError::InvalidBrokerSession);
    }
    Ok(())
}

fn prepare_child(
    source_fd: RawFd,
    target_fd: RawFd,
    uid: u32,
    gid: u32,
    launcher_pid: libc::pid_t,
) -> io::Result<()> {
    #[cfg(not(target_os = "linux"))]
    let _ = launcher_pid;
    if target_fd < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Ota session descriptor overlaps standard IO",
        ));
    }
    if source_fd != target_fd && unsafe { libc::dup2(source_fd, target_fd) } < 0 {
        return Err(io::Error::last_os_error());
    }
    mark_descriptors_cloexec()?;
    set_cloexec(target_fd, false)?;

    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        verify_launcher_parent(launcher_pid)?;
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    let effective_uid = unsafe { libc::geteuid() };
    let effective_gid = unsafe { libc::getegid() };
    if effective_uid == 0 {
        if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
            || unsafe { libc::setgid(gid) } != 0
            || unsafe { libc::setuid(uid) } != 0
        {
            return Err(io::Error::last_os_error());
        }
    } else if effective_uid != uid || effective_gid != gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "launcher cannot switch to configured job principal",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_launcher_parent(expected: libc::pid_t) -> io::Result<()> {
    if unsafe { libc::getppid() } == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "launcher exited while preparing the Ota child",
        ))
    }
}

fn mark_descriptors_cloexec() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
        let result =
            unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(code) if code == libc::ENOSYS || code == libc::EINVAL
        ) {
            return Err(error);
        }
    }

    let limit = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let upper = if limit <= 0 {
        65_536
    } else {
        limit.min(1_048_576) as RawFd
    };
    for descriptor in 3..upper {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags >= 0
            && unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn set_cloexec(descriptor: RawFd, enabled: bool) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let next = if enabled {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, next) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn exit_code(status: ExitStatus) -> u8 {
    if let Some(code) = status.code() {
        return code.clamp(0, 255) as u8;
    }
    use std::os::unix::process::ExitStatusExt;
    status
        .signal()
        .map(|signal| (128 + signal).clamp(1, 255) as u8)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::path::PathBuf;

    use super::*;
    use crate::config::{LauncherConfig, RunAs};

    fn current_peer() -> SessionPeer {
        SessionPeer {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        }
    }

    #[test]
    fn connected_unix_stream_is_required_and_made_non_inheritable() {
        let (stream, _peer) = UnixStream::pair().expect("socket pair");
        let descriptor = stream.into_raw_fd();
        let owned =
            take_connected_unix_stream(descriptor, current_peer()).expect("connected stream");
        let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);

        let (mismatched, _peer) = UnixStream::pair().expect("mismatched pair");
        let descriptor = mismatched.into_raw_fd();
        let mut wrong_peer = current_peer();
        wrong_peer.uid = wrong_peer.uid.saturating_add(1);
        assert!(matches!(
            take_connected_unix_stream(descriptor, wrong_peer),
            Err(LauncherError::BrokerPeerMismatch)
        ));
        unsafe {
            libc::close(descriptor);
        }

        let mut pipe = [0_i32; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        assert!(take_connected_unix_stream(pipe[0], current_peer()).is_err());
        unsafe {
            libc::close(pipe[0]);
            libc::close(pipe[1]);
        }

        let datagram = UnixDatagram::unbound().expect("Unix datagram");
        let datagram_descriptor = datagram.into_raw_fd();
        assert!(take_connected_unix_stream(datagram_descriptor, current_peer()).is_err());
        unsafe {
            libc::close(datagram_descriptor);
        }

        let unconnected = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(unconnected >= 0);
        assert!(take_connected_unix_stream(unconnected, current_peer()).is_err());
        unsafe {
            libc::close(unconnected);
        }

        let standard_alias = unsafe { libc::dup(libc::STDIN_FILENO) };
        assert!(standard_alias >= 3);
        assert!(reject_standard_stream_alias(standard_alias).is_err());
        unsafe {
            libc::close(standard_alias);
        }
    }

    #[test]
    fn bridge_is_bidirectional_and_closes_cleanly() {
        let (mut ota_client, ota_launcher) = UnixStream::pair().expect("ota pair");
        let (broker_launcher, mut broker_server) = UnixStream::pair().expect("broker pair");
        let bridge = start_bridge(&ota_launcher, &broker_launcher).expect("bridge");

        ota_client.write_all(b"challenge").expect("write challenge");
        ota_client.shutdown(Shutdown::Write).expect("ota shutdown");
        let mut challenge = Vec::new();
        broker_server
            .read_to_end(&mut challenge)
            .expect("read challenge");
        assert_eq!(challenge, b"challenge");
        broker_server
            .write_all(b"attestation")
            .expect("write response");
        broker_server
            .shutdown(Shutdown::Write)
            .expect("broker shutdown");
        let mut response = Vec::new();
        ota_client
            .read_to_end(&mut response)
            .expect("read response");
        assert_eq!(response, b"attestation");
        assert!(finish_bridge(bridge).is_ok());
    }

    #[test]
    fn bridge_preserves_core_protocol_frames_byte_for_byte() {
        fn frame(payload: &[u8]) -> Vec<u8> {
            let mut framed = Vec::with_capacity(4 + payload.len());
            framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            framed.extend_from_slice(payload);
            framed
        }

        let request_payloads: [&[u8]; 3] = [
            br#"{"message_kind":"challenge_request"}"#,
            br#"{"message_kind":"authorization_request"}"#,
            br#"{"message_kind":"lease_consume"}"#,
        ];
        let response_payloads: [&[u8]; 4] = [
            br#"{"message_kind":"attestation_response"}"#,
            br#"{"message_kind":"authorization_decision"}"#,
            br#"{"message_kind":"lease_issuance"}"#,
            br#"{"message_kind":"lease_consume_response"}"#,
        ];
        let requests = request_payloads
            .iter()
            .flat_map(|payload| frame(payload))
            .collect::<Vec<_>>();
        let responses = response_payloads
            .iter()
            .flat_map(|payload| frame(payload))
            .collect::<Vec<_>>();

        let (mut ota_client, ota_launcher) = UnixStream::pair().expect("ota pair");
        let (broker_launcher, mut broker_server) = UnixStream::pair().expect("broker pair");
        let bridge = start_bridge(&ota_launcher, &broker_launcher).expect("bridge");

        ota_client.write_all(requests.as_slice()).expect("requests");
        ota_client.shutdown(Shutdown::Write).expect("ota shutdown");
        let mut observed_requests = Vec::new();
        broker_server
            .read_to_end(&mut observed_requests)
            .expect("read requests");
        assert_eq!(observed_requests, requests);

        broker_server
            .write_all(responses.as_slice())
            .expect("responses");
        broker_server
            .shutdown(Shutdown::Write)
            .expect("broker shutdown");
        let mut observed_responses = Vec::new();
        ota_client
            .read_to_end(&mut observed_responses)
            .expect("read responses");
        assert_eq!(observed_responses, responses);
        finish_bridge(bridge).expect("bridge joins");
    }

    #[test]
    fn child_exec_inherits_only_the_ota_session_descriptor() {
        const OTA_DESCRIPTOR: RawFd = 197;
        const BROKER_DESCRIPTOR: RawFd = 198;

        let (broker_launcher, _broker_server) = UnixStream::pair().expect("broker pair");
        assert_eq!(
            unsafe { libc::dup2(broker_launcher.as_raw_fd(), BROKER_DESCRIPTOR) },
            BROKER_DESCRIPTOR
        );

        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let mut environment = std::collections::BTreeMap::new();
        environment.insert(
            String::from("LAUNCHER_SAFE_VALUE"),
            String::from("protected"),
        );
        let config = LauncherConfig {
            schema_version: 1,
            ota_binary: PathBuf::from("/bin/sh"),
            run_as: RunAs { uid, gid },
            environment,
            sessions: Vec::new(),
        };
        let args = vec![
            String::from("-c"),
            format!(
                "test -e /dev/fd/{OTA_DESCRIPTOR} && \
                 test ! -e /dev/fd/{BROKER_DESCRIPTOR} && \
                 test \"$LAUNCHER_SAFE_VALUE\" = protected && \
                 test -z \"${{HOME+x}}\""
            ),
        ];
        let result = launch_inner(
            config,
            BROKER_DESCRIPTOR,
            current_peer(),
            CoreBindingSelection {
                ota_session_descriptor: OTA_DESCRIPTOR,
            },
            args.as_slice(),
        );
        assert_eq!(result.expect("launcher execution"), 0);
    }

    #[test]
    fn production_entrypoint_requires_root_before_session_use() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let config = LauncherConfig {
            schema_version: 1,
            ota_binary: PathBuf::from("/bin/false"),
            run_as: RunAs { uid: 1, gid: 1 },
            environment: std::collections::BTreeMap::new(),
            sessions: Vec::new(),
        };
        assert!(matches!(
            launch(
                config,
                999,
                current_peer(),
                CoreBindingSelection {
                    ota_session_descriptor: 3,
                },
                &[]
            ),
            Err(LauncherError::RootRequired)
        ));
    }

    #[test]
    fn real_bridge_failure_terminates_and_reaps_the_child() {
        let (mut source_writer, source_reader) = UnixStream::pair().expect("source pair");
        let (broken_writer, broken_peer) = UnixStream::pair().expect("broken pair");
        broken_peer
            .shutdown(Shutdown::Both)
            .expect("broken peer shutdown");
        broken_writer
            .shutdown(Shutdown::Write)
            .expect("broken writer shutdown");
        source_writer.write_all(b"x").expect("source payload");
        source_writer
            .shutdown(Shutdown::Write)
            .expect("source shutdown");
        let stopping = AtomicBool::new(false);
        let failure = copy_and_shutdown(source_reader, broken_writer, &stopping)
            .expect_err("broken Unix writer must fail");

        let (sender, events) = mpsc::channel();
        sender.send(Err(failure)).expect("bridge failure event");
        drop(sender);
        let bridge = Bridge {
            upstream: thread::spawn(|| Ok(())),
            downstream: thread::spawn(|| Ok(())),
            stopping: Arc::new(AtomicBool::new(false)),
            events,
        };
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("sleep child");
        assert!(matches!(
            supervise(&mut child, &bridge),
            Err(LauncherError::SessionBridge)
        ));
        assert!(child.try_wait().expect("reaped child").is_some());
        bridge.stopping.store(true, Ordering::Release);
        finish_bridge(bridge).expect("bridge joins");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_launch_drops_uid_gid_and_supplementary_groups() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        const OTA_DESCRIPTOR: RawFd = 195;
        const BROKER_DESCRIPTOR: RawFd = 196;
        const NOBODY: u32 = 65_534;

        let (broker_launcher, _broker_server) = UnixStream::pair().expect("broker pair");
        assert_eq!(
            unsafe { libc::dup2(broker_launcher.as_raw_fd(), BROKER_DESCRIPTOR) },
            BROKER_DESCRIPTOR
        );
        let config = LauncherConfig {
            schema_version: 1,
            ota_binary: PathBuf::from("/bin/sh"),
            run_as: RunAs {
                uid: NOBODY,
                gid: NOBODY,
            },
            environment: std::collections::BTreeMap::new(),
            sessions: Vec::new(),
        };
        let args = vec![
            String::from("-c"),
            String::from(
                "test \"$(/usr/bin/id -u)\" = 65534 && \
                 test \"$(/usr/bin/id -g)\" = 65534 && \
                 test \"$(/usr/bin/id -G)\" = 65534 && \
                 /usr/bin/grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status",
            ),
        ];
        let result = launch_inner(
            config,
            BROKER_DESCRIPTOR,
            current_peer(),
            CoreBindingSelection {
                ota_session_descriptor: OTA_DESCRIPTOR,
            },
            args.as_slice(),
        );
        assert_eq!(result.expect("root launcher execution"), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parent_pid_binding_rejects_a_different_launcher() {
        assert!(verify_launcher_parent(unsafe { libc::getppid() }).is_ok());
        assert!(verify_launcher_parent(i32::MAX).is_err());
    }
}
