use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::model::{EventKind, NormalizedEvent, ParsedTrace};

pub fn read_trace(path: &Path) -> Result<ParsedTrace> {
    let file = File::open(path).with_context(|| format!("opening telemetry {}", path.display()))?;
    let reader: Box<dyn Read> = if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zst"))
    {
        Box::new(zstd::stream::read::Decoder::new(file)?)
    } else {
        Box::new(file)
    };
    parse_jsonl(BufReader::new(reader))
}

fn parse_jsonl(reader: impl BufRead) -> Result<ParsedTrace> {
    let mut trace = ParsedTrace::default();
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("reading telemetry line {}", index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(events)) => {
                for value in events {
                    trace.events.push(normalize(value, index as u64 + 1));
                }
            }
            Ok(value) => trace.events.push(normalize(value, index as u64 + 1)),
            Err(_) => trace.malformed_lines += 1,
        }
    }
    trace.events.sort_by_key(|event| {
        (
            event.timestamp.is_none(),
            event.timestamp.unwrap_or(event.seq),
            event.seq,
        )
    });
    Ok(trace)
}

fn normalize(value: Value, seq: u64) -> NormalizedEvent {
    let phase = field(&value, &["skillsissuePhase", "skillsissue_phase"]).and_then(value_as_string);
    let phase_known = phase.as_deref().is_some_and(|phase| {
        phase.eq_ignore_ascii_case("pre-detonation") || phase.eq_ignore_ascii_case("detonation")
    });
    let pre_detonation = phase
        .as_deref()
        .is_some_and(|phase| phase.eq_ignore_ascii_case("pre-detonation"));
    let root = value
        .get("event")
        .filter(|event| event.is_object())
        .unwrap_or(&value);
    let name = field(root, &["eventName", "event_name", "name", "event"])
        .and_then(value_as_string)
        .unwrap_or_default();
    let timestamp = field(
        root,
        &["timestamp", "timestamp_ns", "timeStamp", "monotonic_ns"],
    )
    .and_then(value_as_u64);
    let pid = field(
        root,
        &[
            "processId",
            "process_id",
            "pid",
            "hostProcessId",
            "host_pid",
        ],
    )
    .and_then(value_as_i64)
    .unwrap_or_default();
    let ppid = field(
        root,
        &[
            "parentProcessId",
            "parent_process_id",
            "ppid",
            "hostParentProcessId",
        ],
    )
    .and_then(value_as_i64);
    let return_value =
        field(root, &["returnValue", "return_value", "retval", "ret"]).and_then(value_as_i64);
    let args = normalize_args(field(root, &["args", "arguments", "parameters"]));
    let kind = classify(&name);

    NormalizedEvent {
        seq,
        timestamp,
        phase_known,
        pre_detonation,
        pid,
        ppid,
        name,
        kind,
        return_value,
        args,
        evidence: flatten_strings(root),
    }
}

fn normalize_args(value: Option<&Value>) -> BTreeMap<String, Value> {
    let mut args = BTreeMap::new();
    match value {
        Some(Value::Array(values)) => {
            for (index, argument) in values.iter().enumerate() {
                if let Value::Object(object) = argument {
                    let name = object
                        .get("name")
                        .and_then(value_as_string)
                        .unwrap_or_else(|| format!("arg{index}"));
                    let value = object
                        .get("value")
                        .or_else(|| object.get("val"))
                        .cloned()
                        .unwrap_or_else(|| argument.clone());
                    args.insert(name, value);
                } else {
                    args.insert(format!("arg{index}"), argument.clone());
                }
            }
        }
        Some(Value::Object(object)) => {
            args.extend(
                object
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
        Some(value) => {
            args.insert("arg0".to_string(), value.clone());
        }
        None => {}
    }
    args
}

fn field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
    let object = value.as_object()?;
    names.iter().find_map(|name| {
        object.get(*name).or_else(|| {
            object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        })
    })
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_as_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn value_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn classify(name: &str) -> EventKind {
    let name = name.to_ascii_lowercase();
    if matches!(name.as_str(), "execve" | "execveat" | "sched_process_exec")
        || name.ends_with("process_exec")
    {
        EventKind::Exec
    } else if matches!(
        name.as_str(),
        "open" | "openat" | "openat2" | "security_file_open"
    ) {
        EventKind::Open
    } else if matches!(
        name.as_str(),
        "read" | "pread" | "pread64" | "readv" | "preadv"
    ) {
        EventKind::Read
    } else if matches!(
        name.as_str(),
        "write"
            | "pwrite"
            | "pwrite64"
            | "writev"
            | "pwritev"
            | "rename"
            | "renameat"
            | "renameat2"
            | "unlink"
            | "unlinkat"
            | "chmod"
            | "fchmod"
            | "fchmodat"
            | "file_modification"
            | "dropped_executable"
    ) {
        EventKind::Write
    } else if name.contains("dns") {
        EventKind::Dns
    } else if name.contains("connect")
        || name.contains("socket")
        || name.contains("net_packet")
        || name.contains("http_request")
        || name.contains("http_response")
        || name.contains("sendto")
        || name.contains("sendmsg")
    {
        EventKind::Network
    } else if name.contains("fork") || matches!(name.as_str(), "clone" | "clone3") {
        EventKind::Process
    } else if matches!(
        name.as_str(),
        "pipe" | "pipe2" | "dup" | "dup2" | "dup3" | "close"
    ) {
        EventKind::Fd
    } else {
        EventKind::Other
    }
}

pub fn flatten_strings(value: &Value) -> String {
    let mut values = Vec::new();
    collect_strings(value, &mut values);
    values.join(" ")
}

fn collect_strings(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(value) => output.push(value.clone()),
        Value::Number(value) => output.push(value.to_string()),
        Value::Array(values) => {
            for value in values {
                collect_strings(value, output);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_strings(value, output);
            }
        }
        Value::Bool(_) | Value::Null => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_camel_case_and_object_arguments() {
        let input =
            r#"{"eventName":"openat","processId":4,"args":{"pathname":"/tmp/a"},"returnValue":7}"#;
        let trace = parse_jsonl(Cursor::new(input)).unwrap();
        assert_eq!(trace.events[0].kind, EventKind::Open);
        assert_eq!(trace.events[0].pid, 4);
        assert_eq!(trace.events[0].args["pathname"], "/tmp/a");
    }

    #[test]
    fn preserves_supervisor_event_phase() {
        let input = r#"{"skillsissuePhase":"pre-detonation","eventName":"openat","processId":4}"#;
        let trace = parse_jsonl(Cursor::new(input)).unwrap();
        assert!(trace.events[0].phase_known);
        assert!(trace.events[0].pre_detonation);
    }

    #[test]
    fn legacy_event_phase_is_unknown_instead_of_detonation() {
        let input = r#"{"eventName":"openat","processId":4}"#;
        let trace = parse_jsonl(Cursor::new(input)).unwrap();
        assert!(!trace.events[0].phase_known);
        assert!(!trace.events[0].pre_detonation);
    }

    #[test]
    fn skips_malformed_lines_but_keeps_valid_events() {
        let input = "not json\n{\"event_name\":\"execve\",\"pid\":1,\"args\":[]}";
        let trace = parse_jsonl(Cursor::new(input)).unwrap();
        assert_eq!(trace.malformed_lines, 1);
        assert_eq!(trace.events.len(), 1);
    }

    #[test]
    fn orders_cross_cpu_events_by_tracee_timestamp() {
        let input = "{\"timestamp\":20,\"eventName\":\"write\",\"processId\":1}\n{\"timestamp\":10,\"eventName\":\"openat\",\"processId\":1}";
        let trace = parse_jsonl(Cursor::new(input)).unwrap();
        assert_eq!(trace.events[0].name, "openat");
        assert_eq!(trace.events[1].name, "write");
        assert_eq!(
            trace.events[0].seq, 2,
            "raw line number remains evidence ID"
        );
    }

    #[test]
    fn classifies_filesystem_mutations_as_writes() {
        for name in [
            "renameat",
            "unlinkat",
            "chmod",
            "file_modification",
            "dropped_executable",
        ] {
            assert_eq!(classify(name), EventKind::Write, "{name}");
        }
        for name in ["pipe", "pipe2", "dup", "dup2", "dup3", "close"] {
            assert_eq!(classify(name), EventKind::Fd, "{name}");
        }
    }
}
