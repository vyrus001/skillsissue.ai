use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceMeta {
    pub source: String,
    pub run_id: Option<String>,
    pub status: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub declared_event_count: Option<u64>,
    pub parsed_event_count: usize,
    pub malformed_lines: usize,
    pub uncompressed_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct TraceEvent {
    pub seq: u64,
    pub source_line: u64,
    pub source_index: usize,
    pub timestamp: Option<u64>,
    pub pid: i64,
    pub ppid: Option<i64>,
    pub process_entity_id: Option<u64>,
    pub parent_entity_id: Option<u64>,
    pub process_name: String,
    pub name: String,
    pub return_value: Option<i64>,
    pub args: BTreeMap<String, Value>,
    pub raw: Value,
}

impl TraceEvent {
    pub fn process_key(&self) -> String {
        self.process_entity_id
            .map(|entity| format!("entity:{entity}"))
            .unwrap_or_else(|| format!("pid:{}", self.pid))
    }

    pub fn timestamp_string(&self) -> Option<String> {
        self.timestamp.map(|value| value.to_string())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EventCategory {
    Process,
    File,
    Socket,
    Fd,
    #[default]
    Other,
}

impl EventCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::File => "file",
            Self::Socket => "socket",
            Self::Fd => "fd",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    Outbound,
    InboundOpen,
    InboundAccept,
    Inbound,
    #[default]
    Unknown,
    NotApplicable,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::InboundOpen => "inbound-open",
            Self::InboundAccept => "inbound-accept",
            Self::Inbound => "inbound",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not-applicable",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Tcp,
    Udp,
    Unix,
    #[default]
    Unknown,
    NotApplicable,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Unix => "unix",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not-applicable",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedEvent {
    pub seq: u64,
    pub order: usize,
    pub source_line: u64,
    pub source_index: usize,
    pub timestamp_ns: Option<String>,
    #[serde(skip)]
    pub timestamp: Option<u64>,
    pub name: String,
    pub process_key: String,
    pub process_entity_id: Option<String>,
    pub pid: i64,
    pub ppid: Option<i64>,
    pub process_name: String,
    pub category: EventCategory,
    pub operation: String,
    pub detail: String,
    pub target: Option<String>,
    pub fd: Option<i64>,
    pub bytes: Option<u64>,
    pub direction: Direction,
    pub transport: Transport,
    pub return_value: Option<i64>,
    pub success: Option<bool>,
    pub notes: Vec<String>,
    pub args: BTreeMap<String, Value>,
    pub raw: Value,
}

#[derive(Clone, Debug, Default)]
pub struct ProcessInfo {
    pub key: String,
    pub entity_id: Option<u64>,
    pub pid: i64,
    pub name: String,
    pub first_timestamp: Option<u64>,
    pub first_seq: u64,
    pub parent_key: Option<String>,
    pub exec_events: Vec<u64>,
    pub derived_from_fork: bool,
}

#[derive(Clone, Debug)]
pub struct ForkRelation {
    pub event_seq: u64,
    pub parent_key: String,
    pub child_key: String,
    pub child_pid: i64,
    pub timestamp: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct TraceData {
    pub meta: SourceMeta,
    pub events: Vec<NormalizedEvent>,
    pub processes: BTreeMap<String, ProcessInfo>,
    pub forks: Vec<ForkRelation>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum GroupMode {
    #[default]
    Target,
    Operation,
    None,
}

impl GroupMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "target" => Some(Self::Target),
            "operation" => Some(Self::Operation),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Operation => "operation",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphSettings {
    pub bucket_ns: u64,
    pub group: GroupMode,
}

impl Default for GraphSettings {
    fn default() -> Self {
        Self {
            bucket_ns: 10_000_000,
            group: GroupMode::Target,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
    pub process_kind: Option<String>,
    pub timestamp_ns: Option<String>,
    pub time_offset_ns: Option<String>,
    pub order: usize,
    pub equal_time_order: usize,
    pub depth: usize,
    pub label: String,
    pub sublabel: String,
    pub command: Option<String>,
    pub process_key: String,
    pub process_name: String,
    pub pid: i64,
    pub category: EventCategory,
    pub operation: String,
    pub target: Option<String>,
    pub direction: Direction,
    pub transport: Transport,
    pub count: usize,
    pub byte_count: u64,
    pub file_descriptors: Vec<i64>,
    pub success_count: usize,
    pub failure_count: usize,
    pub event_ids: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub kind: String,
    pub label: String,
    pub event_ids: Vec<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Facets {
    pub categories: BTreeMap<String, usize>,
    pub operations: BTreeMap<String, usize>,
    pub transports: BTreeMap<String, usize>,
    pub directions: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphModel {
    pub meta: SourceMeta,
    pub settings: GraphSettingsDto,
    pub min_timestamp_ns: Option<String>,
    pub max_timestamp_ns: Option<String>,
    pub event_count: usize,
    pub represented_event_count: usize,
    pub process_count: usize,
    pub activity_node_count: usize,
    pub facets: Facets,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphSettingsDto {
    pub bucket_ns: String,
    pub group: String,
}
