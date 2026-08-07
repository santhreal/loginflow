//! Adversarial: login flows that never complete.
//!
//! A hostile or broken server can accept the TCP connection and then stall
//! forever, trickling bytes or going silent mid-response. The login flow
//! must honor its configured timeout and return an error in bounded wall
//! time instead of hanging the caller's process for as long as the server
//! feels like stalling.

use std::time::{Duration, Instant};

use loginflow::http_fastpath::{perform_http_login, ScaldLoginFlow};
use url::Url;

/// Spawn a TCP listener that accepts connections and then goes completely
/// silent: no response bytes, no close. Returns the bound port. The
/// listener runs until the tokio runtime drops it.
fn spawn_silent_server() -> u16 {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind silent server");
            tx.send(listener.local_addr().unwrap().port()).unwrap();
            loop {
                let (socket, _) = listener.accept().await.expect("accept");
                // Hold the connection open without ever writing a response.
                // Leaking the socket keeps it alive for the runtime's life.
                std::mem::forget(socket);
            }
        });
    });
    rx.recv().expect("server port")
}

/// Spawn a TCP listener that sends a valid HTTP response head and then
/// stalls forever mid-body, so the client's read of the body never finishes.
fn spawn_trickling_server() -> u16 {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind trickling server");
            tx.send(listener.local_addr().unwrap().port()).unwrap();
            loop {
                let (mut socket, _) = listener.accept().await.expect("accept");
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    // Content-Length promises 1MB the server never sends.
                    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1048576\r\n\r\n<html>";
                    let _ = socket.write_all(head.as_bytes()).await;
                    // Then silence: keep the socket open, send nothing more.
                    std::mem::forget(socket);
                });
            }
        });
    });
    rx.recv().expect("server port")
}

fn login_flow_to(port: u16) -> (ScaldLoginFlow, Url) {
    let flow = ScaldLoginFlow {
        url: format!("http://127.0.0.1:{port}/login"),
        method: "POST".to_string(),
        fields: vec![
            ("user".to_string(), "alice".to_string()),
            ("pass".to_string(), "secret".to_string()),
        ],
    };
    let origin = Url::parse(&format!("http://127.0.0.1:{port}/")).expect("origin url");
    (flow, origin)
}

/// Why: a server that accepts and never replies is the canonical "login
/// flow that never completes". The client must give up after the caller's
/// timeout with an error, in wall time close to that timeout. A hang here
/// freezes any scan that drives logins.
#[tokio::test]
async fn silent_server_login_times_out_in_bounded_time() {
    let port = spawn_silent_server();
    let (flow, origin) = login_flow_to(port);

    let start = Instant::now();
    let res = perform_http_login(&flow, &[], &origin, Duration::from_millis(300)).await;
    let elapsed = start.elapsed();

    assert!(res.is_err(), "silent server must produce an error, not a hang");
    assert!(
        elapsed < Duration::from_secs(10),
        "login against a silent server must respect the 300ms timeout, took {elapsed:?}"
    );
}

/// Why: a server that answers the response head but stalls the body is a
/// subtler hang: headers arrive, so naive "got a response" logic thinks the
/// flow completed and waits forever for bytes that never come. The timeout
/// must cover body reads, not just connect+headers.
#[tokio::test]
async fn mid_body_stall_login_times_out_in_bounded_time() {
    let port = spawn_trickling_server();
    let (flow, origin) = login_flow_to(port);

    let start = Instant::now();
    let res = perform_http_login(&flow, &[], &origin, Duration::from_millis(300)).await;
    let elapsed = start.elapsed();

    assert!(
        res.is_err(),
        "mid-body stall must produce an error, not an indefinite body read"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "login against a mid-body stall must respect the 300ms timeout, took {elapsed:?}"
    );
}

/// Why: the positive control. A port that refuses connections must fail
/// immediately and clearly; this distinguishes "timeout honored" (the two
/// tests above) from "every failure looks the same", which would hide the
/// difference between a dead host and a stalling hostile host.
#[tokio::test]
async fn refused_connection_fails_fast_not_timeout() {
    // Port 1 is reserved and refuses on essentially every host.
    let (flow, origin) = login_flow_to(1);

    let start = Instant::now();
    let res = perform_http_login(&flow, &[], &origin, Duration::from_secs(30)).await;
    let elapsed = start.elapsed();

    assert!(res.is_err(), "refused connection must error");
    assert!(
        elapsed < Duration::from_secs(10),
        "connection refused must fail fast, not wait out the timeout, took {elapsed:?}"
    );
}
