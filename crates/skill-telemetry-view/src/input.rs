use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::model::{SourceMeta, TraceEvent};

#[derive(Clone, Copy, Debug)]
pub struct LoadLimits {
    pub max_events: usize,
    pub max_uncompressed_bytes: u64,
    pub max_line_bytes: usize,
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self {
            max_events: 1_000_000,
            max_uncompressed_bytes: 256 * 1024 * 1024,
            max_line_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub struct LoadedTrace {
    pub meta: SourceMeta,
    pub events: Vec<TraceEvent>,
}

pub fn load(path: &Path, limits: LoadLimits) -> Result<LoadedTrace> {
    let (event_path, mut meta) = resolve_input(path)?;
    meta.source = event_path.display().to_string();
    let file = File::open(&event_path)
        .with_context(|| format!("opening telemetry {}", event_path.display()))?;
    let reader: Box<dyn Read> = if event_path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("zst"))
    {
        Box::new(
            zstd::stream::read::Decoder::new(file)
                .with_context(|| format!("decoding {}", event_path.display()))?,
        )
    } else {
        Box::new(file)
    };

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut events = Vec::new();
    let mut source_line = 0_u64;
    let mut total_bytes = 0_u64;
    let mut malformed_lines = 0_usize;
    let mut seq = 0_u64;

    loop {
        line.clear();
        let bounded_line_bytes = u64::try_from(limits.max_line_bytes)
            .unwrap_or(u64::MAX - 1)
            .saturating_add(1);
        let bytes = Read::by_ref(&mut reader)
            .take(bounded_line_bytes)
            .read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        source_line += 1;
        if bytes > limits.max_line_bytes {
            bail!(
                "telemetry line {source_line} exceeds the {} byte line limit",
                limits.max_line_bytes
            );
        }
        total_bytes = total_bytes.saturating_add(bytes as u64);
        if total_bytes > limits.max_uncompressed_bytes {
            bail!(
                "telemetry exceeds the {} byte decompression limit; raise --max-uncompressed-bytes explicitly",
                limits.max_uncompressed_bytes
            );
        }
        if line.trim().is_empty() {
            continue;
        }

        match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(values)) => {
                for (source_index, value) in values.into_iter().enumerate() {
                    seq += 1;
                    events.push(parse_event(value, seq, source_line, source_index));
                    enforce_event_limit(events.len(), limits.max_events)?;
                }
            }
            Ok(value) => {
                seq += 1;
                events.push(parse_event(value, seq, source_line, 0));
                enforce_event_limit(events.len(), limits.max_events)?;
            }
            Err(_) => malformed_lines += 1,
        }
    }

    events.sort_by_key(|event| {
        (
            event.timestamp.is_none(),
            event.timestamp.unwrap_or(event.seq),
            event.seq,
        )
    });
    meta.parsed_event_count = events.len();
    meta.malformed_lines = malformed_lines;
    meta.uncompressed_bytes = total_bytes;

    Ok(LoadedTrace { meta, events })
}

fn enforce_event_limit(count: usize, limit: usize) -> Result<()> {
    if count > limit {
        bail!("telemetry exceeds the {limit} event limit; raise --max-events explicitly");
    }
    Ok(())
}

fn resolve_input(path: &Path) -> Result<(PathBuf, SourceMeta)> {
    if path.is_dir() {
        return resolve_run_directory(path);
    }
    if path.file_name().is_some_and(|name| name == "run.json") {
        let directory = path.parent().context("run.json has no parent directory")?;
        return resolve_run_directory(directory);
    }
    if !path.is_file() {
        bail!(
            "telemetry input does not exist or is not a file: {}",
            path.display()
        );
    }
    Ok((path.to_path_buf(), SourceMeta::default()))
}

fn resolve_run_directory(directory: &Path) -> Result<(PathBuf, SourceMeta)> {
    let run_json_path = directory.join("run.json");
    let run_json: Option<Value> = if run_json_path.is_file() {
        let bytes = std::fs::read(&run_json_path)
            .with_context(|| format!("reading {}", run_json_path.display()))?;
        Some(
            serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", run_json_path.display()))?,
        )
    } else {
        None
    };

    let meta = SourceMeta {
        run_id: run_json
            .as_ref()
            .and_then(|value| string_field(value, "run_id")),
        status: run_json
            .as_ref()
            .and_then(|value| string_field(value, "status")),
        started_at: run_json
            .as_ref()
            .and_then(|value| string_field(value, "started_at")),
        finished_at: run_json
            .as_ref()
            .and_then(|value| string_field(value, "finished_at")),
        declared_event_count: run_json
            .as_ref()
            .and_then(|value| value.get("raw_event_count"))
            .and_then(value_as_u64),
        ..SourceMeta::default()
    };

    let declared_name = run_json
        .as_ref()
        .and_then(|value| string_field(value, "telemetry_path"))
        .and_then(|value| Path::new(&value).file_name().map(|name| name.to_owned()));
    let candidates = declared_name
        .into_iter()
        .map(|name| directory.join(name))
        .chain([
            directory.join("events.jsonl.zst"),
            directory.join("events.partial.jsonl.zst"),
            directory.join("events.jsonl"),
            directory.join("events.partial.jsonl"),
        ]);
    let event_path = candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .with_context(|| {
            format!(
                "no events.jsonl(.zst) or events.partial.jsonl(.zst) in {}",
                directory.display()
            )
        })?;
    Ok((event_path, meta))
}

fn string_field(value: &Value, name: &str) -> Option<String> {
    value.get(name)?.as_str().map(ToOwned::to_owned)
}

fn parse_event(value: Value, seq: u64, source_line: u64, source_index: usize) -> TraceEvent {
    let pre_detonation = field(&value, &["skillsissuePhase", "skillsissue_phase"])
        .and_then(value_as_string)
        .is_some_and(|phase| phase.eq_ignore_ascii_case("pre-detonation"));
    let root = value
        .get("event")
        .filter(|event| event.is_object())
        .unwrap_or(&value);
    TraceEvent {
        seq,
        source_line,
        source_index,
        pre_detonation,
        timestamp: field(
            root,
            &["timestamp", "timestamp_ns", "timeStamp", "monotonic_ns"],
        )
        .and_then(value_as_u64),
        pid: field(
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
        .unwrap_or_default(),
        ppid: field(
            root,
            &[
                "parentProcessId",
                "parent_process_id",
                "ppid",
                "hostParentProcessId",
            ],
        )
        .and_then(value_as_i64),
        process_entity_id: field(root, &["processEntityId", "process_entity_id"])
            .and_then(value_as_u64),
        parent_entity_id: field(root, &["parentEntityId", "parent_entity_id"])
            .and_then(value_as_u64)
            .filter(|value| *value != 0),
        process_name: field(root, &["processName", "process_name", "comm"])
            .and_then(value_as_string)
            .unwrap_or_default(),
        name: field(root, &["eventName", "event_name", "name", "event"])
            .and_then(value_as_string)
            .unwrap_or_else(|| "unknown".to_string()),
        return_value: field(root, &["returnValue", "return_value", "retval", "ret"])
            .and_then(value_as_i64),
        args: normalize_args(field(root, &["args", "arguments", "parameters"])),
        raw: value,
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

pub(crate) fn field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
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

pub(crate) fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub(crate) fn value_as_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

pub(crate) fn value_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn normalizes_tracee_arguments_and_stably_orders_equal_timestamps() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            temp.as_file(),
            "{{\"timestamp\":20,\"eventName\":\"write\",\"processId\":2,\"args\":[{{\"name\":\"fd\",\"value\":4}}]}}"
        )
        .unwrap();
        writeln!(
            temp.as_file(),
            "{{\"timestamp\":10,\"eventName\":\"openat\",\"processId\":2,\"args\":{{\"pathname\":\"/tmp/x\"}}}}"
        )
        .unwrap();
        writeln!(
            temp.as_file(),
            "{{\"timestamp\":10,\"eventName\":\"close\",\"processId\":2}}"
        )
        .unwrap();

        let loaded = load(temp.path(), LoadLimits::default()).unwrap();
        assert_eq!(loaded.events[0].name, "openat");
        assert_eq!(loaded.events[1].name, "close");
        assert_eq!(loaded.events[2].name, "write");
        assert_eq!(loaded.events[0].args["pathname"], "/tmp/x");
        assert_eq!(loaded.events[0].seq, 2);
        assert_eq!(loaded.events[1].seq, 3);
    }

    #[test]
    fn loads_supervisor_phase_annotation() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            temp.as_file(),
            "{{\"skillsissuePhase\":\"pre-detonation\",\"eventName\":\"openat\",\"processId\":2}}"
        )
        .unwrap();
        let loaded = load(temp.path(), LoadLimits::default()).unwrap();
        assert!(loaded.events[0].pre_detonation);
    }

    #[test]
    fn accepts_zstandard_jsonl() {
        let temp = tempfile::Builder::new().suffix(".zst").tempfile().unwrap();
        {
            let mut encoder = zstd::stream::write::Encoder::new(temp.as_file(), 1).unwrap();
            writeln!(encoder, "{{\"eventName\":\"execve\",\"processId\":1}}").unwrap();
            encoder.finish().unwrap();
        }
        let loaded = load(temp.path(), LoadLimits::default()).unwrap();
        assert_eq!(loaded.events.len(), 1);
    }

    #[test]
    fn rejects_an_oversized_line_before_parsing_it() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), "{\"eventName\":\"123456789\"}\n").unwrap();
        let error = load(
            temp.path(),
            LoadLimits {
                max_line_bytes: 16,
                ..LoadLimits::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("line 1 exceeds"));
    }
}
