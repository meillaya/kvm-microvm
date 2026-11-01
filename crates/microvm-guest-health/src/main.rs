//! Tiny static HTTP health server for microvm guest rootfs.
//!
//! Uses only `std::net::TcpListener`; no external HTTP framework.
//! Designed to compile as a static musl binary for Firecracker guests.

use std::env;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process;

/// Build an HTTP/1.1 response string from a status code and body.
fn http_response(status: u16, reason: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        reason,
        body.len(),
        body,
    )
}

/// Route a request line (e.g. "GET /health HTTP/1.1") to an HTTP response.
fn handle_request(request_line: &str) -> String {
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return http_response(400, "Bad Request", "bad request");
    }

    let method = parts[0];
    let path = parts[1];

    if method != "GET" {
        return http_response(405, "Method Not Allowed", "method not allowed");
    }

    match path {
        "/health" => http_response(200, "OK", "ok"),
        "/" => http_response(200, "OK", "Hello from microvm guest"),
        _ => http_response(404, "Not Found", "not found"),
    }
}

/// Handle a single TCP connection: read the request line, route, respond.
fn handle_connection(stream: TcpStream) {
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }

    let response = handle_request(&request_line);

    let mut writer = stream;
    let _ = writer.write_all(response.as_bytes());
    let _ = writer.flush();
}

fn main() {
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let addr = format!("0.0.0.0:{port}");

    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| {
        eprintln!("failed to bind {addr}: {e}");
        process::exit(1);
    });

    eprintln!("microvm-guest-health listening on {addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_connection(s),
            Err(e) => eprintln!("connection error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_endpoint_returns_200_ok() {
        let resp = handle_request("GET /health HTTP/1.1");
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.ends_with("ok"));
        assert!(resp.contains("Content-Length: 2"));
    }

    #[test]
    fn root_endpoint_returns_greeting() {
        let resp = handle_request("GET / HTTP/1.1");
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.ends_with("Hello from microvm guest"));
        assert!(resp.contains("Content-Length: 24"));
    }

    #[test]
    fn unknown_path_returns_404() {
        let resp = handle_request("GET /nope HTTP/1.1");
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(resp.ends_with("not found"));
    }

    #[test]
    fn non_get_method_returns_405() {
        let resp = handle_request("POST /health HTTP/1.1");
        assert!(resp.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(resp.ends_with("method not allowed"));
    }

    #[test]
    fn malformed_request_returns_400() {
        let resp = handle_request("");
        assert!(resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(resp.ends_with("bad request"));
    }

    #[test]
    fn response_contains_connection_close_header() {
        let resp = handle_request("GET /health HTTP/1.1");
        assert!(resp.contains("Connection: close\r\n"));
    }

    #[test]
    fn response_contains_content_type_header() {
        let resp = handle_request("GET / HTTP/1.1");
        assert!(resp.contains("Content-Type: text/plain; charset=utf-8\r\n"));
    }
}
