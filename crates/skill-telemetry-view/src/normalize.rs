use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::input::{LoadedTrace, value_as_i64, value_as_string, value_as_u64};
use crate::model::{
    Direction, EventCategory, ForkRelation, NormalizedEvent, ProcessInfo, TraceData, TraceEvent,
    Transport,
};

#[derive(Clone, Debug)]
struct FdTarget {
    label: String,
    close_on_exec: bool,
}

#[derive(Debug)]
struct Classification {
    category: EventCategory,
    operation: String,
    detail: String,
    target: Option<String>,
    fd: Option<i64>,
    bytes: Option<u64>,
    direction: Direction,
    transport: Transport,
    notes: Vec<String>,
}

pub fn normalize(loaded: LoadedTrace) -> TraceData {
    let LoadedTrace { meta, events } = loaded;
    let (mut processes, forks) = discover_processes(&events);
    let fork_by_event = forks
        .iter()
        .map(|fork| (fork.event_seq, fork.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut fd_tables = BTreeMap::<String, BTreeMap<i64, FdTarget>>::new();
    let mut inherited_tables = BTreeMap::<String, BTreeMap<i64, FdTarget>>::new();
    let mut normalized = Vec::with_capacity(events.len());

    for (order, event) in events.into_iter().enumerate() {
        let process_key = event.process_key();
        if !fd_tables.contains_key(&process_key) {
            let inherited = inherited_tables.remove(&process_key).unwrap_or_default();
            fd_tables.insert(process_key.clone(), inherited);
        }
        let table = fd_tables.get(&process_key).expect("fd table was inserted");
        let mut classification = classify_event(&event, table);
        if processes
            .get(&process_key)
            .is_some_and(|process| process.derived_from_fork)
        {
            classification
                .notes
                .push("process identity is derived from a recorded fork".to_string());
        }

        mutate_fd_table(&event, fd_tables.get_mut(&process_key).unwrap());
        if let Some(fork) = fork_by_event.get(&event.seq) {
            let snapshot = fd_tables.get(&process_key).cloned().unwrap_or_default();
            inherited_tables.insert(fork.child_key.clone(), snapshot);
        }
        let timestamp_ns = event.timestamp_string();
        let TraceEvent {
            seq,
            source_line,
            source_index,
            timestamp,
            pre_detonation,
            pid,
            ppid,
            process_entity_id,
            process_name,
            name,
            return_value,
            args,
            raw,
            ..
        } = event;
        normalized.push(NormalizedEvent {
            seq,
            order,
            source_line,
            source_index,
            timestamp_ns,
            timestamp,
            pre_detonation,
            name,
            process_key: process_key.clone(),
            process_entity_id: process_entity_id.map(|value| value.to_string()),
            pid,
            ppid,
            process_name,
            category: classification.category,
            operation: classification.operation,
            detail: classification.detail,
            target: classification.target,
            fd: classification.fd,
            bytes: classification.bytes,
            direction: classification.direction,
            transport: classification.transport,
            return_value,
            success: return_value.map(|value| value >= 0),
            notes: classification.notes,
            args,
            raw,
        });
    }

    for process in processes.values_mut() {
        process.exec_events.sort_by_key(|seq| {
            normalized
                .iter()
                .find(|event| event.seq == *seq)
                .map(|event| event.order)
                .unwrap_or(usize::MAX)
        });
    }

    TraceData {
        meta,
        events: normalized,
        processes,
        forks,
    }
}

fn discover_processes(events: &[TraceEvent]) -> (BTreeMap<String, ProcessInfo>, Vec<ForkRelation>) {
    let mut processes = BTreeMap::<String, ProcessInfo>::new();
    let mut first_ppids = BTreeMap::<String, Option<i64>>::new();

    for event in events {
        let key = event.process_key();
        let entry = processes.entry(key.clone()).or_insert_with(|| ProcessInfo {
            key: key.clone(),
            entity_id: event.process_entity_id,
            pid: event.pid,
            name: event.process_name.clone(),
            first_timestamp: event.timestamp,
            first_seq: event.seq,
            parent_key: event
                .parent_entity_id
                .map(|entity| format!("entity:{entity}")),
            exec_events: Vec::new(),
            derived_from_fork: false,
        });
        first_ppids.entry(key.clone()).or_insert(event.ppid);
        if !event.process_name.is_empty() {
            entry.name.clone_from(&event.process_name);
        }
        if is_exec(&event.name) {
            entry.exec_events.push(event.seq);
        }
    }

    let mut by_pid = BTreeMap::<i64, Vec<(Option<u64>, u64, String)>>::new();
    for process in processes.values() {
        by_pid.entry(process.pid).or_default().push((
            process.first_timestamp,
            process.first_seq,
            process.key.clone(),
        ));
    }
    for candidates in by_pid.values_mut() {
        candidates.sort_by_key(|(timestamp, seq, _)| {
            (timestamp.is_none(), timestamp.unwrap_or(*seq), *seq)
        });
    }

    let mut forks = Vec::new();
    for event in events.iter().filter(|event| is_fork(&event.name)) {
        let Some(child_pid) = child_pid(event) else {
            continue;
        };
        let parent_key = event.process_key();
        let child_key = by_pid
            .get(&child_pid)
            .and_then(|candidates| {
                candidates
                    .iter()
                    .find(|(timestamp, seq, key)| {
                        *key != parent_key
                            && event_at_or_before(event.timestamp, event.seq, *timestamp, *seq)
                    })
                    .map(|(_, _, key)| key.clone())
            })
            .unwrap_or_else(|| format!("fork:{}:pid:{child_pid}", event.seq));

        if !processes.contains_key(&child_key) {
            processes.insert(
                child_key.clone(),
                ProcessInfo {
                    key: child_key.clone(),
                    entity_id: None,
                    pid: child_pid,
                    name: format!("pid {child_pid}"),
                    first_timestamp: event.timestamp,
                    first_seq: event.seq,
                    parent_key: Some(parent_key.clone()),
                    exec_events: Vec::new(),
                    derived_from_fork: true,
                },
            );
        } else if let Some(child) = processes.get_mut(&child_key) {
            child.parent_key = Some(parent_key.clone());
        }
        forks.push(ForkRelation {
            event_seq: event.seq,
            parent_key,
            child_key,
            child_pid,
            timestamp: event.timestamp,
        });
    }

    // Fall back to namespace PPID only when Tracee did not provide entity or fork identity.
    let keys = processes.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        let needs_parent = processes
            .get(&key)
            .is_some_and(|process| process.parent_key.is_none());
        if !needs_parent {
            continue;
        }
        let Some(ppid) = first_ppids
            .get(&key)
            .copied()
            .flatten()
            .filter(|pid| *pid > 0)
        else {
            continue;
        };
        let child = processes.get(&key).expect("process key exists");
        let parent = by_pid.get(&ppid).and_then(|candidates| {
            candidates
                .iter()
                .rev()
                .find(|(timestamp, seq, candidate)| {
                    *candidate != key
                        && event_at_or_before(
                            *timestamp,
                            *seq,
                            child.first_timestamp,
                            child.first_seq,
                        )
                })
                .map(|(_, _, key)| key.clone())
        });
        if let Some(parent) = parent {
            processes.get_mut(&key).unwrap().parent_key = Some(parent);
        }
    }

    (processes, forks)
}

fn event_at_or_before(
    left_timestamp: Option<u64>,
    left_seq: u64,
    right_timestamp: Option<u64>,
    right_seq: u64,
) -> bool {
    match (left_timestamp, right_timestamp) {
        (Some(left), Some(right)) => (left, left_seq) <= (right, right_seq),
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => left_seq <= right_seq,
    }
}

fn classify_event(event: &TraceEvent, fds: &BTreeMap<i64, FdTarget>) -> Classification {
    let lower = event.name.to_ascii_lowercase();
    let mut result = Classification {
        category: EventCategory::Other,
        operation: lower.clone(),
        detail: event.name.clone(),
        target: None,
        fd: None,
        bytes: None,
        direction: Direction::NotApplicable,
        transport: Transport::NotApplicable,
        notes: Vec::new(),
    };

    if is_exec(&lower) {
        result.category = EventCategory::Process;
        result.operation = "exec".to_string();
        result.target = arg_string(event, &["cmdpath", "pathname", "path", "filename"]);
        result.detail = arg(event, &["argv"])
            .map(compact_value)
            .unwrap_or_else(|| result.target.clone().unwrap_or_else(|| "exec".to_string()));
        return result;
    }
    if is_fork(&lower) {
        result.category = EventCategory::Process;
        result.operation = "fork".to_string();
        result.target = child_pid(event).map(|pid| format!("pid {pid}"));
        result.detail = result
            .target
            .clone()
            .unwrap_or_else(|| "child identity unavailable".to_string());
        return result;
    }
    if is_exit(&lower) {
        result.category = EventCategory::Process;
        result.operation = "exit".to_string();
        result.detail = event
            .return_value
            .map(|value| format!("exit {value}"))
            .unwrap_or_else(|| "process exit".to_string());
        return result;
    }

    if is_file_open(&lower) {
        let flags = arg_string(event, &["flags"]).unwrap_or_default();
        result.category = EventCategory::File;
        result.operation = if lower == "creat" {
            "create/open-write"
        } else {
            classify_open(&flags)
        }
        .to_string();
        result.target = arg_string(
            event,
            &[
                "pathname",
                "syscall_pathname",
                "file_path",
                "path",
                "filename",
            ],
        );
        result.fd = event.return_value.filter(|value| *value >= 0);
        result.detail = detail_with_target(&result.operation, result.target.as_deref());
        if flags.is_empty() {
            result
                .notes
                .push("open access mode is unavailable in this event".to_string());
        }
        return result;
    }
    if is_read(&lower) || is_write(&lower) {
        result.category = EventCategory::File;
        result.operation = if is_read(&lower) { "read" } else { "write" }.to_string();
        result.fd = arg_i64(event, &["fd"]);
        result.bytes = event
            .return_value
            .filter(|value| *value > 0)
            .map(|value| value as u64);
        if let Some(fd) = result.fd {
            if let Some(target) = fds.get(&fd) {
                result.target = Some(target.label.clone());
                result
                    .notes
                    .push(format!("target attributed by replaying fd {fd}"));
            } else {
                result.target = Some(format!("fd {fd} (unresolved)"));
                result.notes.push(
                    "the read/write event contains no path and no prior captured FD mapping"
                        .to_string(),
                );
            }
        }
        result.detail = detail_with_target(&result.operation, result.target.as_deref());
        return result;
    }
    if is_file_lifecycle(&lower) {
        result.category = EventCategory::File;
        result.operation = lifecycle_operation(&lower).to_string();
        result.target = lifecycle_target(event, &lower);
        result.detail = detail_with_target(&result.operation, result.target.as_deref());
        return result;
    }

    if is_fd_event(&lower) {
        result.category = EventCategory::Fd;
        result.operation = if lower.starts_with("pipe") {
            "pipe"
        } else if lower.starts_with("dup") {
            "duplicate"
        } else {
            "close"
        }
        .to_string();
        result.fd = arg_i64(event, &["fd", "oldfd"]);
        result.target = fd_event_target(event, fds, &lower);
        result.detail = detail_with_target(&result.operation, result.target.as_deref());
        return result;
    }

    if is_socket_event(&lower) {
        return classify_socket(event, &lower, fds);
    }

    result.target = first_generic_target(event);
    result.detail = detail_with_target(&result.operation, result.target.as_deref());
    result
}

fn classify_socket(
    event: &TraceEvent,
    lower: &str,
    fds: &BTreeMap<i64, FdTarget>,
) -> Classification {
    let fd = arg_i64(event, &["sockfd", "fd"]);
    let address = socket_address(event);
    let socket_type = arg_string(event, &["type", "sock_type", "socket_type"]);
    let mut notes = Vec::new();
    let transport = classify_transport(
        address.as_ref().map(|value| &value.0),
        socket_type.as_deref(),
        lower,
    );
    let direction = if lower.contains("connect") {
        Direction::Outbound
    } else if matches!(lower, "bind" | "security_socket_bind" | "listen") {
        Direction::InboundOpen
    } else if lower.starts_with("accept") || lower.contains("socket_accept") {
        Direction::InboundAccept
    } else if lower.starts_with("recv") {
        Direction::Inbound
    } else if lower.starts_with("send") && address.is_some() {
        Direction::Outbound
    } else if lower.contains("dns") {
        packet_direction(event, &mut notes)
    } else {
        Direction::Unknown
    };
    let operation = if lower.contains("dns") {
        "dns"
    } else if lower.contains("connect") {
        "connect"
    } else if lower.contains("bind") {
        "bind"
    } else if lower == "listen" {
        "listen"
    } else if lower.starts_with("accept") || lower.contains("socket_accept") {
        "accept"
    } else if lower.starts_with("send") {
        "send"
    } else if lower.starts_with("recv") {
        "receive"
    } else {
        "socket"
    }
    .to_string();

    let mut target = address.map(|(_, label)| label);
    if target.is_none() && lower.contains("dns") {
        target = dns_target(event);
    }
    if target.is_none()
        && let Some(fd) = fd
    {
        target = fds.get(&fd).map(|target| target.label.clone());
    }
    if matches!(transport, Transport::Unknown) {
        notes.push(
            "transport is unknown because the event lacks a usable socket family/type pair"
                .to_string(),
        );
    }
    if matches!(direction, Direction::Unknown) {
        notes.push("direction is not stated unambiguously by this event".to_string());
    }
    let detail = format!(
        "{} · {} · {}{}",
        operation,
        transport.as_str(),
        direction.as_str(),
        target
            .as_deref()
            .map(|value| format!(" · {value}"))
            .unwrap_or_default()
    );
    Classification {
        category: EventCategory::Socket,
        operation,
        detail,
        target,
        fd,
        bytes: event
            .return_value
            .filter(|value| *value > 0)
            .map(|value| value as u64),
        direction,
        transport,
        notes,
    }
}

fn mutate_fd_table(event: &TraceEvent, fds: &mut BTreeMap<i64, FdTarget>) {
    let lower = event.name.to_ascii_lowercase();
    if is_file_open(&lower) {
        if let Some(fd) = event.return_value.filter(|value| *value >= 0) {
            let label = arg_string(
                event,
                &[
                    "pathname",
                    "syscall_pathname",
                    "file_path",
                    "path",
                    "filename",
                ],
            )
            .unwrap_or_else(|| format!("fd {fd} (path unavailable)"));
            let flags = arg(event, &["flags"]);
            fds.insert(
                fd,
                FdTarget {
                    label,
                    close_on_exec: flags.is_some_and(has_close_on_exec),
                },
            );
        }
    } else if lower == "close" {
        if event.return_value.is_none_or(|value| value >= 0)
            && let Some(fd) = arg_i64(event, &["fd"])
        {
            fds.remove(&fd);
        }
    } else if lower.starts_with("dup") && event.return_value.is_none_or(|value| value >= 0) {
        let old = arg_i64(event, &["oldfd", "fd"]);
        let new =
            arg_i64(event, &["newfd"]).or_else(|| event.return_value.filter(|value| *value >= 0));
        if let (Some(new), Some(mut target)) = (new, old.and_then(|fd| fds.get(&fd).cloned())) {
            target.close_on_exec =
                lower == "dup3" && arg(event, &["flags"]).is_some_and(has_close_on_exec);
            fds.insert(new, target);
        }
    } else if lower.starts_with("pipe") && event.return_value.is_none_or(|value| value >= 0) {
        if let Some(values) = arg(event, &["pipefd", "fds"]).and_then(Value::as_array) {
            let close_on_exec = arg(event, &["flags"]).is_some_and(has_close_on_exec);
            if let Some(read_fd) = values.first().and_then(value_as_i64) {
                fds.insert(
                    read_fd,
                    FdTarget {
                        label: format!("pipe:{}:read", event.seq),
                        close_on_exec,
                    },
                );
            }
            if let Some(write_fd) = values.get(1).and_then(value_as_i64) {
                fds.insert(
                    write_fd,
                    FdTarget {
                        label: format!("pipe:{}:write", event.seq),
                        close_on_exec,
                    },
                );
            }
        }
    } else if lower == "socket" {
        if let Some(fd) = event.return_value.filter(|value| *value >= 0) {
            let family = arg_string(event, &["domain", "family"])
                .unwrap_or_else(|| "family unknown".to_string());
            let socket_type = arg_string(event, &["type", "sock_type"])
                .unwrap_or_else(|| "type unknown".to_string());
            fds.insert(
                fd,
                FdTarget {
                    label: format!("socket {family}/{socket_type}"),
                    close_on_exec: arg(event, &["type", "flags"]).is_some_and(has_close_on_exec),
                },
            );
        }
    } else if lower.contains("connect")
        && event.return_value.is_some_and(|value| value >= 0)
        && let (Some(fd), Some((_, address))) =
            (arg_i64(event, &["sockfd", "fd"]), socket_address(event))
    {
        let close_on_exec = fds.get(&fd).is_some_and(|target| target.close_on_exec);
        fds.insert(
            fd,
            FdTarget {
                label: address,
                close_on_exec,
            },
        );
    }

    if is_exec(&lower) {
        fds.retain(|_, target| !target.close_on_exec);
    }
}

fn has_close_on_exec(value: &Value) -> bool {
    value_as_string(value).is_some_and(|value| value.to_ascii_uppercase().contains("CLOEXEC"))
        || value_as_i64(value).is_some_and(|value| value & 0o2000000 != 0)
}

fn arg<'a>(event: &'a TraceEvent, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| {
        event.args.get(*name).or_else(|| {
            event
                .args
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
        })
    })
}

fn arg_string(event: &TraceEvent, names: &[&str]) -> Option<String> {
    arg(event, names).and_then(value_as_string)
}

fn arg_i64(event: &TraceEvent, names: &[&str]) -> Option<i64> {
    arg(event, names).and_then(value_as_i64)
}

fn child_pid(event: &TraceEvent) -> Option<i64> {
    arg_i64(
        event,
        &[
            "child_ns_pid",
            "child_process_ns_pid",
            "child_pid",
            "child_tid",
        ],
    )
}

fn is_exec(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(name.as_str(), "execve" | "execveat" | "sched_process_exec")
        || name.ends_with("process_exec")
}

fn is_fork(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("fork") || matches!(name.as_str(), "clone" | "clone3")
}

fn is_exit(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "sched_process_exit" || name.ends_with("process_exit") || name == "exit_group"
}

fn is_file_open(name: &str) -> bool {
    matches!(
        name,
        "open" | "openat" | "openat2" | "creat" | "security_file_open"
    )
}

fn is_read(name: &str) -> bool {
    matches!(
        name,
        "read" | "pread" | "pread64" | "readv" | "preadv" | "preadv2"
    )
}

fn is_write(name: &str) -> bool {
    matches!(
        name,
        "write" | "pwrite" | "pwrite64" | "writev" | "pwritev" | "pwritev2"
    )
}

fn is_file_lifecycle(name: &str) -> bool {
    matches!(
        name,
        "rename"
            | "renameat"
            | "renameat2"
            | "unlink"
            | "unlinkat"
            | "chmod"
            | "fchmod"
            | "fchmodat"
            | "truncate"
            | "ftruncate"
            | "mkdir"
            | "mkdirat"
            | "rmdir"
            | "file_modification"
            | "dropped_executable"
    )
}

fn is_fd_event(name: &str) -> bool {
    name.starts_with("pipe") || name.starts_with("dup") || name == "close"
}

fn is_socket_event(name: &str) -> bool {
    name.contains("socket")
        || name.contains("connect")
        || name.contains("net_packet")
        || name.contains("dns")
        || name.starts_with("send")
        || name.starts_with("recv")
        || matches!(name, "bind" | "listen" | "accept" | "accept4")
}

fn classify_open(flags: &str) -> &'static str {
    let flags = flags.to_ascii_uppercase();
    if flags.contains("O_TRUNC") {
        "truncate/open-write"
    } else if flags.contains("O_CREAT") {
        "create/open-write"
    } else if flags.contains("O_RDWR") {
        "open-read-write"
    } else if flags.contains("O_WRONLY") || flags.contains("O_APPEND") {
        "open-write"
    } else if flags.contains("O_RDONLY") {
        "open-read"
    } else {
        "open-unknown"
    }
}

fn lifecycle_operation(name: &str) -> &'static str {
    if name.starts_with("rename") {
        "rename"
    } else if name.starts_with("unlink") || name == "rmdir" {
        "delete"
    } else if name.contains("chmod") {
        "permission-change"
    } else if name.contains("truncate") {
        "truncate"
    } else if name.starts_with("mkdir") {
        "create-directory"
    } else if name == "dropped_executable" {
        "create-executable"
    } else {
        "modify"
    }
}

fn lifecycle_target(event: &TraceEvent, name: &str) -> Option<String> {
    if name.starts_with("rename") {
        let old = arg_string(event, &["oldpath", "old_path", "pathname"]);
        let new = arg_string(event, &["newpath", "new_path"]);
        return match (old, new) {
            (Some(old), Some(new)) => Some(format!("{old} → {new}")),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
    }
    arg_string(
        event,
        &[
            "pathname",
            "file_path",
            "path",
            "filename",
            "syscall_pathname",
        ],
    )
}

fn fd_event_target(
    event: &TraceEvent,
    fds: &BTreeMap<i64, FdTarget>,
    name: &str,
) -> Option<String> {
    if name.starts_with("pipe") {
        return arg(event, &["pipefd", "fds"]).map(compact_value);
    }
    if name.starts_with("dup") {
        let old = arg_i64(event, &["oldfd", "fd"]);
        let new = arg_i64(event, &["newfd"]).or(event.return_value.filter(|value| *value >= 0));
        return match (old, new) {
            (Some(old), Some(new)) => Some(format!("fd {old} → fd {new}")),
            _ => None,
        };
    }
    arg_i64(event, &["fd"]).map(|fd| {
        fds.get(&fd)
            .map(|target| format!("fd {fd} · {}", target.label))
            .unwrap_or_else(|| format!("fd {fd} (unresolved)"))
    })
}

fn first_generic_target(event: &TraceEvent) -> Option<String> {
    arg_string(
        event,
        &[
            "pathname",
            "file_path",
            "path",
            "filename",
            "address",
            "addr",
        ],
    )
}

fn socket_address(event: &TraceEvent) -> Option<(String, String)> {
    let value = arg(
        event,
        &["remote_addr", "local_addr", "addr", "sockaddr", "address"],
    )?;
    if let Some(text) = value_as_string(value) {
        return Some(("unknown".to_string(), text));
    }
    let object = value.as_object()?;
    let family = object
        .get("sa_family")
        .or_else(|| object.get("family"))
        .and_then(value_as_string)
        .unwrap_or_else(|| "unknown".to_string());
    let upper = family.to_ascii_uppercase();
    if upper.contains("UNIX") {
        let path = object
            .get("sun_path")
            .or_else(|| object.get("path"))
            .and_then(value_as_string)
            .unwrap_or_else(|| "unnamed Unix socket".to_string());
        return Some((family, path));
    }
    let address = object
        .get("sin_addr")
        .or_else(|| object.get("sin6_addr"))
        .or_else(|| object.get("address"))
        .or_else(|| object.get("addr"))
        .and_then(value_as_string);
    let port = object
        .get("sin_port")
        .or_else(|| object.get("sin6_port"))
        .or_else(|| object.get("port"))
        .and_then(value_as_u64);
    let label = match (address, port) {
        (Some(address), Some(port)) if address.contains(':') => format!("[{address}]:{port}"),
        (Some(address), Some(port)) => format!("{address}:{port}"),
        (Some(address), None) => address,
        (None, Some(port)) => format!("port {port}"),
        (None, None) => compact_value(value),
    };
    Some((family, label))
}

fn classify_transport(family: Option<&String>, socket_type: Option<&str>, name: &str) -> Transport {
    let family = family.map(|value| value.to_ascii_uppercase());
    let socket_type = socket_type.unwrap_or_default().to_ascii_uppercase();
    if family
        .as_deref()
        .is_some_and(|value| value.contains("UNIX"))
    {
        Transport::Unix
    } else if family.as_deref().is_some_and(|value| {
        value.contains("INET") || value.contains("IPV4") || value.contains("IPV6")
    }) {
        if socket_type.contains("STREAM") {
            Transport::Tcp
        } else if socket_type.contains("DGRAM") || socket_type.contains("DATAGRAM") {
            Transport::Udp
        } else {
            Transport::Unknown
        }
    } else if name.contains("tcp") {
        Transport::Tcp
    } else if name.contains("udp") {
        Transport::Udp
    } else {
        Transport::Unknown
    }
}

fn packet_direction(event: &TraceEvent, notes: &mut Vec<String>) -> Direction {
    let Some(metadata) = arg(event, &["metadata"]).and_then(Value::as_object) else {
        return Direction::Unknown;
    };
    let Some(value) = metadata.get("direction") else {
        return Direction::Unknown;
    };
    let Some(direction) = value.as_str() else {
        notes.push(
            "packet direction is numeric in this capture and is left unknown without a schema label"
                .to_string(),
        );
        return Direction::Unknown;
    };
    match direction.to_ascii_lowercase().as_str() {
        "egress" | "outbound" | "out" => Direction::Outbound,
        "ingress" | "inbound" | "in" => Direction::Inbound,
        _ => Direction::Unknown,
    }
}

fn dns_target(event: &TraceEvent) -> Option<String> {
    let proto = arg(event, &["proto_dns", "dns"])?;
    let questions = proto.get("questions")?.as_array()?;
    let names = questions
        .iter()
        .filter_map(|question| question.get("name"))
        .filter_map(value_as_string)
        .collect::<BTreeSet<_>>();
    if names.is_empty() {
        None
    } else {
        Some(names.into_iter().collect::<Vec<_>>().join(", "))
    }
}

fn detail_with_target(operation: &str, target: Option<&str>) -> String {
    match target {
        Some(target) => format!("{operation} · {}", truncate(target, 180)),
        None => operation.to_string(),
    }
}

fn compact_value(value: &Value) -> String {
    truncate(
        &serde_json::to_string(value).unwrap_or_else(|_| "<unavailable>".to_string()),
        240,
    )
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut output = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    output.push('…');
    output
}

#[cfg(test)]
mod tests {
    use crate::input::{LoadLimits, load};

    use super::*;

    fn normalize_jsonl(input: &str) -> TraceData {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), input).unwrap();
        normalize(load(temp.path(), LoadLimits::default()).unwrap())
    }

    #[test]
    fn replays_file_descriptors_and_distinguishes_file_operations() {
        let trace = normalize_jsonl(
            r#"{"timestamp":1,"eventName":"openat","processId":2,"processEntityId":20,"returnValue":4,"args":[{"name":"pathname","value":"/tmp/data"},{"name":"flags","value":"O_RDWR|O_CREAT"}]}
{"timestamp":2,"eventName":"read","processId":2,"processEntityId":20,"returnValue":7,"args":[{"name":"fd","value":4}]}
{"timestamp":3,"eventName":"write","processId":2,"processEntityId":20,"returnValue":3,"args":[{"name":"fd","value":4}]}
{"timestamp":4,"eventName":"renameat","processId":2,"processEntityId":20,"returnValue":0,"args":{"oldpath":"/tmp/data","newpath":"/tmp/done"}}
"#,
        );
        assert_eq!(trace.events[0].operation, "create/open-write");
        assert_eq!(trace.events[1].operation, "read");
        assert_eq!(trace.events[1].target.as_deref(), Some("/tmp/data"));
        assert_eq!(trace.events[2].operation, "write");
        assert_eq!(trace.events[3].operation, "rename");
        assert_eq!(
            trace.events[3].target.as_deref(),
            Some("/tmp/data → /tmp/done")
        );
    }

    #[test]
    fn constructs_fork_relationship_from_namespace_child_pid() {
        let trace = normalize_jsonl(
            r#"{"timestamp":1,"eventName":"sched_process_exec","processId":1,"processEntityId":10,"args":{"pathname":"/bin/parent"}}
{"timestamp":2,"eventName":"sched_process_fork","processId":1,"processEntityId":10,"args":{"child_ns_pid":2}}
{"timestamp":3,"eventName":"sched_process_exec","processId":2,"processEntityId":20,"parentEntityId":10,"args":{"pathname":"/bin/child"}}
"#,
        );
        assert_eq!(trace.forks.len(), 1);
        assert_eq!(trace.forks[0].parent_key, "entity:10");
        assert_eq!(trace.forks[0].child_key, "entity:20");
        assert_eq!(
            trace.processes["entity:20"].parent_key.as_deref(),
            Some("entity:10")
        );
    }

    #[test]
    fn classifies_socket_family_transport_and_direction_without_guessing() {
        let trace = normalize_jsonl(
            r#"{"timestamp":1,"eventName":"security_socket_connect","processId":1,"processEntityId":10,"returnValue":0,"args":{"sockfd":3,"type":"SOCK_STREAM","remote_addr":{"sa_family":"AF_INET","sin_addr":"1.2.3.4","sin_port":443}}}
{"timestamp":2,"eventName":"security_socket_connect","processId":1,"processEntityId":10,"returnValue":0,"args":{"sockfd":4,"type":"SOCK_DGRAM","remote_addr":{"sa_family":"AF_INET6","sin6_addr":"::1","sin6_port":53}}}
{"timestamp":3,"eventName":"connect","processId":1,"processEntityId":10,"returnValue":-2,"args":{"sockfd":5,"addr":{"sa_family":"AF_UNIX","sun_path":"/tmp/a.sock"}}}
{"timestamp":4,"eventName":"bind","processId":1,"processEntityId":10,"returnValue":0,"args":{"sockfd":6,"addr":{"sa_family":"AF_INET","sin_addr":"0.0.0.0","sin_port":8080}}}
{"timestamp":5,"eventName":"accept4","processId":1,"processEntityId":10,"returnValue":7,"args":{"sockfd":6,"addr":{"sa_family":"AF_INET","sin_addr":"10.0.0.4","sin_port":51000}}}
"#,
        );
        assert_eq!(trace.events[0].transport, Transport::Tcp);
        assert_eq!(trace.events[0].direction, Direction::Outbound);
        assert_eq!(trace.events[1].transport, Transport::Udp);
        assert_eq!(trace.events[2].transport, Transport::Unix);
        assert_eq!(trace.events[3].direction, Direction::InboundOpen);
        assert_eq!(trace.events[3].transport, Transport::Unknown);
        assert_eq!(trace.events[4].direction, Direction::InboundAccept);
    }
}
