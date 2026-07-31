use std::collections::BTreeMap;

pub use skills_core::{
    AssessmentRecord, FindingRecord, PlatformEvidenceRecord, PlatformRecord, RunRecord,
    SCHEMA_VERSION,
};

pub trait RunRecordExt {
    fn is_completed(&self) -> bool;
    fn is_untraced(&self) -> bool;
    fn is_failed(&self) -> bool;
    fn evidence_time(&self) -> String;
}

impl RunRecordExt for RunRecord {
    fn is_completed(&self) -> bool {
        matches!(
            self.status.trim().to_ascii_lowercase().as_str(),
            "captured"
                | "captured_untraced"
                | "completed"
                | "complete"
                | "succeeded"
                | "success"
                | "finished"
                | "failed"
        )
    }

    fn is_untraced(&self) -> bool {
        self.status.trim().eq_ignore_ascii_case("captured_untraced")
    }

    fn is_failed(&self) -> bool {
        self.status.trim().eq_ignore_ascii_case("failed")
    }

    fn evidence_time(&self) -> String {
        [
            self.finished_at.as_ref(),
            self.started_at.as_ref(),
            Some(&self.queued_at),
        ]
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
    }
}

#[derive(Clone, Debug)]
pub struct Analysis {
    pub assessment: AssessmentRecord,
    pub findings: Vec<FindingRecord>,
    pub platform_evidence: Vec<PlatformEvidenceRecord>,
    pub platform_candidates: Vec<PlatformRecord>,
}

#[derive(Clone, Debug, Default)]
pub struct NormalizedEvent {
    pub seq: u64,
    pub timestamp: Option<u64>,
    pub pre_detonation: bool,
    pub pid: i64,
    pub ppid: Option<i64>,
    pub name: String,
    pub kind: EventKind,
    pub return_value: Option<i64>,
    pub args: BTreeMap<String, serde_json::Value>,
    pub evidence: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum EventKind {
    Exec,
    Open,
    Read,
    Write,
    Process,
    Fd,
    Network,
    Dns,
    #[default]
    Other,
}

#[derive(Clone, Debug, Default)]
pub struct ParsedTrace {
    pub events: Vec<NormalizedEvent>,
    pub malformed_lines: usize,
}

pub fn stable_id(namespace: &str, parts: &[&str]) -> String {
    skills_core::stable_id_v1(namespace, parts)
}
