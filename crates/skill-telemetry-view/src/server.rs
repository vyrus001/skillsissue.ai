use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::graph::build_graph;
use crate::model::{GraphSettings, GroupMode, NormalizedEvent, TraceData};

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const STYLE_CSS: &str = include_str!("../web/style.css");
const CONFIG_JS: &str = "window.SKILLSISSUE_VIEWER = { mode: \"server\" };\n";
const MAX_REQUEST_LINE: usize = 8 * 1024;
const MAX_HEADERS: usize = 64 * 1024;
const MAX_PAGE_SIZE: usize = 500;
const MAX_EVENT_SELECTION: usize = 200;
const MAX_BUCKET_NS: u64 = 60_000_000_000;

pub fn serve(trace: TraceData, host: IpAddr, port: u16) -> Result<()> {
    if !host.is_loopback() {
        bail!("refusing to expose attacker-controlled telemetry on non-loopback address {host}");
    }
    let listener = TcpListener::bind(SocketAddr::new(host, port))
        .with_context(|| format!("binding telemetry viewer on {host}:{port}"))?;
    let address = listener.local_addr()?;
    println!("Telemetry viewer: http://{address}");
    println!("Press Ctrl-C to stop.");
    let state = Arc::new(trace);
    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                if let Err(error) = handle_connection(&mut stream, &state) {
                    eprintln!("request failed: {error:#}");
                }
            }
            Err(error) => eprintln!("connection failed: {error}"),
        }
    }
    Ok(())
}

fn handle_connection(stream: &mut TcpStream, trace: &TraceData) -> Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(15)))?;
    let mut reader = BufReader::new(&mut *stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if request_line.len() > MAX_REQUEST_LINE {
        write_response(
            stream,
            414,
            "text/plain; charset=utf-8",
            b"request URI too long",
        )?;
        return Ok(());
    }
    let mut header_bytes = 0_usize;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        header_bytes += bytes;
        if bytes == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if header_bytes > MAX_HEADERS {
            write_response(
                stream,
                431,
                "text/plain; charset=utf-8",
                b"headers too large",
            )?;
            return Ok(());
        }
    }
    drop(reader);

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or("/");
    if method != "GET" {
        write_response(
            stream,
            405,
            "text/plain; charset=utf-8",
            b"method not allowed",
        )?;
        return Ok(());
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match path {
        "/" | "/index.html" => write_response(
            stream,
            200,
            "text/html; charset=utf-8",
            INDEX_HTML.as_bytes(),
        )?,
        "/app.js" => write_response(
            stream,
            200,
            "text/javascript; charset=utf-8",
            APP_JS.as_bytes(),
        )?,
        "/config.js" => write_response(
            stream,
            200,
            "text/javascript; charset=utf-8",
            CONFIG_JS.as_bytes(),
        )?,
        "/style.css" => {
            write_response(stream, 200, "text/css; charset=utf-8", STYLE_CSS.as_bytes())?
        }
        "/api/graph" => {
            let params = parse_query(query);
            let bucket_ns = params
                .get("bucket_ns")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(10_000_000)
                .min(MAX_BUCKET_NS);
            let group = params
                .get("group")
                .and_then(|value| GroupMode::parse(value))
                .unwrap_or_default();
            let model = build_graph(trace, GraphSettings { bucket_ns, group });
            write_json(stream, 200, &model)?;
        }
        "/api/event" => {
            let params = parse_query(query);
            let seq = params
                .get("seq")
                .and_then(|value| value.parse::<u64>().ok());
            match seq.and_then(|seq| trace.events.iter().find(|event| event.seq == seq)) {
                Some(event) => write_json(stream, 200, event)?,
                None => write_json(
                    stream,
                    404,
                    &ErrorResponse {
                        error: "event not found",
                    },
                )?,
            }
        }
        "/api/events" => {
            let params = parse_query(query);
            if let Some(ids) = params.get("ids") {
                let requested = ids
                    .split(',')
                    .filter_map(|value| value.parse::<u64>().ok())
                    .take(MAX_EVENT_SELECTION)
                    .collect::<Vec<_>>();
                let events = requested
                    .iter()
                    .filter_map(|seq| trace.events.iter().find(|event| event.seq == *seq))
                    .collect::<Vec<_>>();
                write_json(
                    stream,
                    200,
                    &EventSelection {
                        requested: requested.len(),
                        events,
                    },
                )?;
                return Ok(());
            }
            let offset = params
                .get("offset")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or_default()
                .min(trace.events.len());
            let limit = params
                .get("limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, MAX_PAGE_SIZE);
            let end = offset.saturating_add(limit).min(trace.events.len());
            write_json(
                stream,
                200,
                &EventPage {
                    offset,
                    limit,
                    total: trace.events.len(),
                    events: &trace.events[offset..end],
                },
            )?;
        }
        "/api/health" => write_json(
            stream,
            200,
            &Health {
                ok: true,
                events: trace.events.len(),
            },
        )?,
        _ => write_response(stream, 404, "text/plain; charset=utf-8", b"not found")?,
    }
    Ok(())
}

fn parse_query(query: &str) -> std::collections::BTreeMap<String, String> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| part.split_once('=').unwrap_or((part, "")))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn write_json(stream: &mut TcpStream, status: u16, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    write_response(stream, status, "application/json; charset=utf-8", &bytes)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        414 => "URI Too Long",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

#[derive(Serialize)]
struct EventPage<'a> {
    offset: usize,
    limit: usize,
    total: usize,
    events: &'a [NormalizedEvent],
}

#[derive(Serialize)]
struct EventSelection<'a> {
    requested: usize,
    events: Vec<&'a NormalizedEvent>,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    error: &'a str,
}

#[derive(Serialize)]
struct Health {
    ok: bool,
    events: usize,
}
