use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    Direction, EventCategory, Facets, GraphEdge, GraphModel, GraphNode, GraphSettings,
    GraphSettingsDto, GroupMode, NormalizedEvent, ProcessInfo, TraceData, Transport,
};

#[derive(Clone, Debug)]
struct Anchor {
    id: String,
    timestamp: Option<u64>,
    order: usize,
    seq: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ActivityKey {
    owner: String,
    category: EventCategory,
    operation: String,
    direction: Direction,
    transport: Transport,
    target: String,
    bucket: u64,
    unique: u64,
    pre_detonation: bool,
}

#[derive(Clone, Debug)]
struct ActivityGroup<'a> {
    owner: Anchor,
    events: Vec<&'a NormalizedEvent>,
    targets: BTreeSet<String>,
}

pub fn build_graph(trace: &TraceData, settings: GraphSettings) -> GraphModel {
    let min_timestamp = trace
        .events
        .iter()
        .filter_map(|event| event.timestamp)
        .min();
    let max_timestamp = trace
        .events
        .iter()
        .filter_map(|event| event.timestamp)
        .max();
    let events_by_seq = trace
        .events
        .iter()
        .map(|event| (event.seq, event))
        .collect::<BTreeMap<_, _>>();

    let mut nodes = Vec::<GraphNode>::new();
    let mut edges = Vec::<GraphEdge>::new();
    let mut anchors = BTreeMap::<String, Vec<Anchor>>::new();
    let mut consumed = BTreeSet::<u64>::new();

    for process in trace.processes.values() {
        let mut process_anchors = Vec::<Anchor>::new();
        let first_exec_order = process
            .exec_events
            .first()
            .and_then(|seq| events_by_seq.get(seq))
            .map(|event| event.order);
        if process.exec_events.is_empty()
            || first_exec_order.is_some_and(|order| process_first_order(process, trace) < order)
        {
            let order = process_first_order(process, trace);
            let id = format!("process:{}:observed", safe_id(&process.key));
            let anchor = Anchor {
                id,
                timestamp: process.first_timestamp,
                order,
                seq: process.first_seq,
            };
            nodes.push(process_node(
                &anchor,
                process,
                "observed",
                Vec::new(),
                None,
                events_by_seq
                    .get(&process.first_seq)
                    .is_some_and(|event| event.pre_detonation),
            ));
            process_anchors.push(anchor);
        }

        for seq in &process.exec_events {
            let Some(event) = events_by_seq.get(seq) else {
                continue;
            };
            let id = format!("exec:{seq}");
            let label = event
                .target
                .as_deref()
                .and_then(path_basename)
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| {
                    if event.process_name.is_empty() {
                        "exec".to_string()
                    } else {
                        event.process_name.clone()
                    }
                });
            let command = command_line(event);
            let anchor = Anchor {
                id,
                timestamp: event.timestamp,
                order: event.order,
                seq: event.seq,
            };
            let mut node = process_node(
                &anchor,
                process,
                "exec",
                vec![event.seq],
                Some((
                    label,
                    command.clone().unwrap_or_else(|| event.detail.clone()),
                    command,
                )),
                event.pre_detonation,
            );
            node.target.clone_from(&event.target);
            node.success_count = usize::from(event.success == Some(true));
            node.failure_count = usize::from(event.success == Some(false));
            nodes.push(node);
            consumed.insert(event.seq);
            process_anchors.push(anchor);
        }
        process_anchors.sort_by_key(|anchor| {
            (
                anchor.timestamp.is_none(),
                anchor.timestamp.unwrap_or(anchor.seq),
                anchor.order,
                anchor.id.clone(),
            )
        });
        anchors.insert(process.key.clone(), process_anchors);
    }

    // Same-process image changes form an explicit descending exec chain.
    for process_anchors in anchors.values() {
        for pair in process_anchors.windows(2) {
            edges.push(GraphEdge {
                id: format!("edge:exec:{}:{}", pair[0].id, pair[1].id),
                source: pair[0].id.clone(),
                target: pair[1].id.clone(),
                kind: "exec".to_string(),
                label: "exec".to_string(),
                event_ids: Vec::new(),
            });
        }
    }

    // The first observed image of a child descends from the parent's active image.
    for process in trace.processes.values() {
        let Some(child_anchor) = anchors.get(&process.key).and_then(|values| values.first()) else {
            continue;
        };
        let fork = trace
            .forks
            .iter()
            .find(|fork| fork.child_key == process.key);
        let parent_key = fork
            .map(|fork| &fork.parent_key)
            .or(process.parent_key.as_ref());
        let Some(parent_key) = parent_key else {
            continue;
        };
        let at_timestamp = fork
            .and_then(|fork| fork.timestamp)
            .or(child_anchor.timestamp);
        let at_order = fork
            .and_then(|fork| events_by_seq.get(&fork.event_seq))
            .map(|event| event.order)
            .unwrap_or(child_anchor.order);
        let Some(parent_anchor) = active_anchor(anchors.get(parent_key), at_timestamp, at_order)
        else {
            continue;
        };
        let event_ids = fork.map(|fork| vec![fork.event_seq]).unwrap_or_default();
        consumed.extend(event_ids.iter().copied());
        edges.push(GraphEdge {
            id: format!("edge:spawn:{}:{}", parent_anchor.id, child_anchor.id),
            source: parent_anchor.id.clone(),
            target: child_anchor.id.clone(),
            kind: "spawn".to_string(),
            label: if fork.is_some() { "fork" } else { "parent" }.to_string(),
            event_ids,
        });
    }

    assign_process_depths(&mut nodes, &edges);
    let process_depths = nodes
        .iter()
        .filter(|node| node.kind == "process")
        .map(|node| (node.id.clone(), node.depth))
        .collect::<BTreeMap<_, _>>();

    let mut groups = BTreeMap::<ActivityKey, ActivityGroup<'_>>::new();
    for event in trace
        .events
        .iter()
        .filter(|event| !consumed.contains(&event.seq))
    {
        let owner = active_anchor(
            anchors.get(&event.process_key),
            event.timestamp,
            event.order,
        )
        .cloned()
        .unwrap_or_else(|| Anchor {
            id: format!("process:{}:observed", safe_id(&event.process_key)),
            timestamp: event.timestamp,
            order: event.order,
            seq: event.seq,
        });
        let bucket = match (event.timestamp, min_timestamp) {
            (Some(timestamp), Some(minimum)) if settings.bucket_ns > 0 => {
                timestamp.saturating_sub(minimum) / settings.bucket_ns
            }
            (Some(timestamp), Some(minimum)) => timestamp.saturating_sub(minimum),
            _ => u64::MAX,
        };
        let grouped_target = match settings.group {
            GroupMode::Target => event.target.clone().unwrap_or_default(),
            GroupMode::Operation | GroupMode::None => String::new(),
        };
        let unique = if matches!(settings.group, GroupMode::None) {
            event.seq
        } else {
            0
        };
        let key = ActivityKey {
            owner: owner.id.clone(),
            category: event.category,
            operation: event.operation.clone(),
            direction: event.direction,
            transport: event.transport,
            target: grouped_target,
            bucket,
            unique,
            pre_detonation: event.pre_detonation,
        };
        let group = groups.entry(key).or_insert_with(|| ActivityGroup {
            owner,
            events: Vec::new(),
            targets: BTreeSet::new(),
        });
        if let Some(target) = &event.target {
            group.targets.insert(target.clone());
        }
        group.events.push(event);
    }

    let mut activity_index = 0_usize;
    let mut activity_edges = Vec::<(usize, String, String, String)>::new();
    for (key, mut group) in groups {
        group.events.sort_by_key(|event| event.order);
        let first = group.events[0];
        let process_depth = process_depths
            .get(&group.owner.id)
            .copied()
            .unwrap_or_default();
        let target = match group.targets.len() {
            0 => None,
            1 => group.targets.into_iter().next(),
            count => Some(format!("{count} targets")),
        };
        let id = format!("activity:{activity_index}");
        activity_index += 1;
        let count = group.events.len();
        let byte_count = group.events.iter().filter_map(|event| event.bytes).sum();
        let file_descriptors = group
            .events
            .iter()
            .filter_map(|event| event.fd)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let success_count = group
            .events
            .iter()
            .filter(|event| event.success == Some(true))
            .count();
        let failure_count = group
            .events
            .iter()
            .filter(|event| event.success == Some(false))
            .count();
        let label = activity_label(&key.operation, key.transport, key.direction, count);
        let sublabel = match target.as_deref() {
            Some(target) => format!("{} · {}", first.process_name, truncate(target, 100)),
            None => first.process_name.clone(),
        };
        nodes.push(GraphNode {
            id: id.clone(),
            kind: "activity".to_string(),
            process_kind: None,
            timestamp_ns: first.timestamp_ns.clone(),
            time_offset_ns: offset_string(first.timestamp, min_timestamp),
            order: first.order,
            equal_time_order: 0,
            depth: process_depth,
            pre_detonation: first.pre_detonation,
            label,
            sublabel,
            command: None,
            process_key: first.process_key.clone(),
            process_name: first.process_name.clone(),
            pid: first.pid,
            category: first.category,
            operation: first.operation.clone(),
            target,
            direction: first.direction,
            transport: first.transport,
            count,
            byte_count,
            file_descriptors,
            success_count,
            failure_count,
            event_ids: group.events.iter().map(|event| event.seq).collect(),
        });
        activity_edges.push((first.order, group.owner.id, id, key.operation.clone()));
    }

    // Force-directed layouts expose process ownership directly. Connecting every
    // activity node to its active process image keeps file and socket behavior
    // semantically adjacent without encoding chronology as a synthetic chain.
    activity_edges.sort();
    for (_, source, target, label) in activity_edges {
        edges.push(GraphEdge {
            id: format!("edge:activity:{source}:{target}"),
            source,
            target,
            kind: "activity".to_string(),
            label,
            event_ids: Vec::new(),
        });
    }

    for node in &mut nodes {
        if node.time_offset_ns.is_none() {
            let timestamp = node
                .timestamp_ns
                .as_deref()
                .and_then(|value| value.parse::<u64>().ok());
            node.time_offset_ns = offset_string(timestamp, min_timestamp);
        }
    }

    nodes.sort_by_key(|node| {
        let timestamp = node
            .timestamp_ns
            .as_deref()
            .and_then(|value| value.parse::<u64>().ok());
        (
            timestamp.is_none(),
            timestamp.unwrap_or(node.order as u64),
            node.order,
            node.id.clone(),
        )
    });
    assign_equal_time_order(&mut nodes);
    edges.sort_by(|left, right| left.id.cmp(&right.id));

    let represented = nodes
        .iter()
        .flat_map(|node| node.event_ids.iter().copied())
        .chain(edges.iter().flat_map(|edge| edge.event_ids.iter().copied()))
        .collect::<BTreeSet<_>>();
    let facets = build_facets(&trace.events);

    GraphModel {
        meta: trace.meta.clone(),
        settings: GraphSettingsDto {
            bucket_ns: settings.bucket_ns.to_string(),
            group: settings.group.as_str().to_string(),
        },
        min_timestamp_ns: min_timestamp.map(|value| value.to_string()),
        max_timestamp_ns: max_timestamp.map(|value| value.to_string()),
        event_count: trace.events.len(),
        pre_detonation_event_count: trace
            .events
            .iter()
            .filter(|event| event.pre_detonation)
            .count(),
        represented_event_count: represented.len(),
        process_count: trace.processes.len(),
        activity_node_count: activity_index,
        facets,
        nodes,
        edges,
    }
}

fn process_node(
    anchor: &Anchor,
    process: &ProcessInfo,
    process_kind: &str,
    event_ids: Vec<u64>,
    override_text: Option<(String, String, Option<String>)>,
    pre_detonation: bool,
) -> GraphNode {
    let (label, sublabel, command) = override_text.unwrap_or_else(|| {
        let label = if process.name.is_empty() {
            format!("pid {}", process.pid)
        } else {
            process.name.clone()
        };
        let sublabel = if process.derived_from_fork {
            format!("pid {} · forked; no child event observed", process.pid)
        } else {
            format!("pid {} · observed process image", process.pid)
        };
        (label, sublabel, None)
    });
    GraphNode {
        id: anchor.id.clone(),
        kind: "process".to_string(),
        process_kind: Some(process_kind.to_string()),
        timestamp_ns: anchor.timestamp.map(|value| value.to_string()),
        time_offset_ns: None,
        order: anchor.order,
        equal_time_order: 0,
        depth: 0,
        pre_detonation,
        label,
        sublabel,
        command,
        process_key: process.key.clone(),
        process_name: process.name.clone(),
        pid: process.pid,
        category: EventCategory::Process,
        operation: process_kind.to_string(),
        target: None,
        direction: Direction::NotApplicable,
        transport: Transport::NotApplicable,
        count: event_ids.len(),
        byte_count: 0,
        file_descriptors: Vec::new(),
        success_count: 0,
        failure_count: 0,
        event_ids,
    }
}

fn command_line(event: &NormalizedEvent) -> Option<String> {
    let argv = event.args.get("argv")?.as_array()?;
    let parts = argv
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    (!parts.is_empty()).then(|| truncate(&parts.join(" "), 1_000))
}

fn process_first_order(process: &ProcessInfo, trace: &TraceData) -> usize {
    trace
        .events
        .iter()
        .find(|event| event.process_key == process.key)
        .map(|event| event.order)
        .unwrap_or(process.first_seq as usize)
}

fn active_anchor(
    anchors: Option<&Vec<Anchor>>,
    timestamp: Option<u64>,
    order: usize,
) -> Option<&Anchor> {
    let anchors = anchors?;
    anchors
        .iter()
        .rev()
        .find(|anchor| match (anchor.timestamp, timestamp) {
            (Some(anchor_time), Some(event_time)) => {
                (anchor_time, anchor.order) <= (event_time, order)
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => anchor.order <= order,
        })
        .or_else(|| anchors.first())
}

fn assign_process_depths(nodes: &mut [GraphNode], edges: &[GraphEdge]) {
    let process_ids = nodes
        .iter()
        .filter(|node| node.kind == "process")
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let mut depths = process_ids
        .iter()
        .map(|id| (id.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    let process_edges = edges
        .iter()
        .filter(|edge| {
            edge.kind != "activity"
                && process_ids.contains(&edge.source)
                && process_ids.contains(&edge.target)
        })
        .collect::<Vec<_>>();
    for _ in 0..process_ids.len() {
        let mut changed = false;
        for edge in &process_edges {
            let candidate = depths.get(&edge.source).copied().unwrap_or_default() + 1;
            let target = depths.entry(edge.target.clone()).or_default();
            if candidate > *target {
                *target = candidate;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for node in nodes.iter_mut().filter(|node| node.kind == "process") {
        node.depth = depths.get(&node.id).copied().unwrap_or_default();
    }
}

fn assign_equal_time_order(nodes: &mut [GraphNode]) {
    let mut counts = BTreeMap::<Option<String>, usize>::new();
    for node in nodes {
        let count = counts.entry(node.timestamp_ns.clone()).or_default();
        node.equal_time_order = *count;
        *count += 1;
    }
}

fn build_facets(events: &[NormalizedEvent]) -> Facets {
    let mut facets = Facets::default();
    for event in events {
        *facets
            .categories
            .entry(event.category.as_str().to_string())
            .or_default() += 1;
        *facets
            .operations
            .entry(event.operation.clone())
            .or_default() += 1;
        if !matches!(event.transport, Transport::NotApplicable) {
            *facets
                .transports
                .entry(event.transport.as_str().to_string())
                .or_default() += 1;
        }
        if !matches!(event.direction, Direction::NotApplicable) {
            *facets
                .directions
                .entry(event.direction.as_str().to_string())
                .or_default() += 1;
        }
    }
    facets
}

fn offset_string(timestamp: Option<u64>, minimum: Option<u64>) -> Option<String> {
    timestamp
        .zip(minimum)
        .map(|(timestamp, minimum)| timestamp.saturating_sub(minimum).to_string())
}

fn activity_label(
    operation: &str,
    transport: Transport,
    direction: Direction,
    count: usize,
) -> String {
    let mut parts = Vec::new();
    if !matches!(transport, Transport::NotApplicable) {
        parts.push(transport.as_str().to_string());
    }
    parts.push(operation.to_string());
    if !matches!(direction, Direction::NotApplicable) {
        parts.push(direction.as_str().to_string());
    }
    let mut label = parts.join(" · ");
    if count > 1 {
        label.push_str(&format!(" ×{count}"));
    }
    label
}

fn path_basename(path: &str) -> Option<String> {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .map(str::to_string)
}

fn safe_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ':') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        value.to_string()
    } else {
        value
            .chars()
            .take(max_chars.saturating_sub(1))
            .chain(std::iter::once('…'))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::input::{LoadLimits, load};
    use crate::normalize::normalize;

    use super::*;

    fn trace(input: &str) -> TraceData {
        let temp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp.path(), input).unwrap();
        normalize(load(temp.path(), LoadLimits::default()).unwrap())
    }

    #[test]
    fn graph_relationships_descend_and_represent_every_event() {
        let trace = trace(
            r#"{"timestamp":1,"eventName":"sched_process_exec","processId":1,"processEntityId":10,"processName":"parent","args":{"pathname":"/bin/parent","argv":["/bin/parent","--serve"]}}
{"timestamp":2,"eventName":"sched_process_fork","processId":1,"processEntityId":10,"processName":"parent","args":{"child_ns_pid":2}}
{"timestamp":3,"eventName":"sched_process_exec","processId":2,"processEntityId":20,"parentEntityId":10,"processName":"child","args":{"pathname":"/bin/child"}}
{"timestamp":4,"eventName":"openat","processId":2,"processEntityId":20,"processName":"child","returnValue":3,"args":{"pathname":"/tmp/a","flags":"O_RDONLY"}}
"#,
        );
        let graph = build_graph(&trace, GraphSettings::default());
        assert_eq!(graph.represented_event_count, graph.event_count);
        let parent = graph.nodes.iter().find(|node| node.id == "exec:1").unwrap();
        let child = graph.nodes.iter().find(|node| node.id == "exec:3").unwrap();
        assert_eq!(parent.command.as_deref(), Some("/bin/parent --serve"));
        assert_eq!(parent.target.as_deref(), Some("/bin/parent"));
        assert!(child.depth > parent.depth);
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "spawn"
                && edge.source == parent.id
                && edge.target == child.id
                && edge.event_ids == [2]
        }));
    }

    #[test]
    fn equal_timestamp_layout_inputs_are_deterministic() {
        let trace = trace(
            r#"{"timestamp":10,"eventName":"openat","processId":1,"processEntityId":10,"processName":"p","returnValue":3,"args":{"pathname":"/a","flags":"O_RDONLY"}}
{"timestamp":10,"eventName":"openat","processId":1,"processEntityId":10,"processName":"p","returnValue":4,"args":{"pathname":"/b","flags":"O_RDONLY"}}
{"timestamp":10,"eventName":"write","processId":1,"processEntityId":10,"processName":"p","returnValue":1,"args":{"fd":4}}
"#,
        );
        let settings = GraphSettings {
            bucket_ns: 0,
            group: GroupMode::None,
        };
        let first = build_graph(&trace, settings);
        let second = build_graph(&trace, settings);
        let first_inputs = first
            .nodes
            .iter()
            .map(|node| (&node.id, node.order, node.equal_time_order, node.depth))
            .collect::<Vec<_>>();
        let second_inputs = second
            .nodes
            .iter()
            .map(|node| (&node.id, node.order, node.equal_time_order, node.depth))
            .collect::<Vec<_>>();
        assert_eq!(first_inputs, second_inputs);
        assert_eq!(
            first
                .nodes
                .iter()
                .map(|node| node.equal_time_order)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn aggregation_keeps_all_underlying_event_ids() {
        let trace = trace(
            r#"{"timestamp":1,"eventName":"read","processId":1,"processEntityId":10,"processName":"p","returnValue":1,"args":{"fd":3}}
{"timestamp":2,"eventName":"read","processId":1,"processEntityId":10,"processName":"p","returnValue":1,"args":{"fd":3}}
{"timestamp":3,"eventName":"read","processId":1,"processEntityId":10,"processName":"p","returnValue":1,"args":{"fd":3}}
"#,
        );
        let graph = build_graph(
            &trace,
            GraphSettings {
                bucket_ns: 10,
                group: GroupMode::Target,
            },
        );
        assert_eq!(graph.activity_node_count, 1);
        assert_eq!(graph.represented_event_count, 3);
        let activity = graph
            .nodes
            .iter()
            .find(|node| node.kind == "activity")
            .unwrap();
        assert_eq!(activity.event_ids, [1, 2, 3]);
        assert_eq!(activity.byte_count, 3);
        assert_eq!(activity.file_descriptors, [3]);
        assert_eq!(activity.success_count, 3);
        assert_eq!(activity.failure_count, 0);
    }

    #[test]
    fn phase_filter_metadata_keeps_pre_and_post_activity_separate() {
        let trace = trace(
            r#"{"skillsissuePhase":"pre-detonation","timestamp":1,"eventName":"read","processId":1,"processEntityId":10,"processName":"p","returnValue":1,"args":{"fd":3}}
{"skillsissuePhase":"detonation","timestamp":2,"eventName":"read","processId":1,"processEntityId":10,"processName":"p","returnValue":1,"args":{"fd":3}}
"#,
        );
        let graph = build_graph(
            &trace,
            GraphSettings {
                bucket_ns: 10,
                group: GroupMode::Target,
            },
        );
        assert_eq!(graph.pre_detonation_event_count, 1);
        assert_eq!(graph.activity_node_count, 2);
        assert!(
            graph
                .nodes
                .iter()
                .any(|node| node.process_kind.as_deref() == Some("observed")
                    && node.pre_detonation)
        );
        assert!(
            graph
                .nodes
                .iter()
                .filter(|node| node.kind == "activity")
                .any(|node| node.pre_detonation)
        );
        assert!(
            graph
                .nodes
                .iter()
                .filter(|node| node.kind == "activity")
                .any(|node| !node.pre_detonation)
        );
    }

    #[test]
    fn activity_edges_connect_directly_to_the_owning_process() {
        let trace = trace(
            r#"{"timestamp":1,"eventName":"sched_process_exec","processId":1,"processEntityId":10,"processName":"p","args":{"pathname":"/bin/p"}}
{"timestamp":2,"eventName":"read","processId":1,"processEntityId":10,"processName":"p","returnValue":1,"args":{"fd":3}}
{"timestamp":3,"eventName":"write","processId":1,"processEntityId":10,"processName":"p","returnValue":1,"args":{"fd":4}}
"#,
        );
        let graph = build_graph(
            &trace,
            GraphSettings {
                bucket_ns: 0,
                group: GroupMode::None,
            },
        );
        let read = graph
            .nodes
            .iter()
            .find(|node| node.event_ids == [2])
            .unwrap();
        let write = graph
            .nodes
            .iter()
            .find(|node| node.event_ids == [3])
            .unwrap();
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "activity"
                && edge.source == "exec:1"
                && edge.target == read.id
                && edge.label == "read"
        }));
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == "activity"
                && edge.source == "exec:1"
                && edge.target == write.id
                && edge.label == "write"
        }));
    }
}
