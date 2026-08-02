use serde::{Deserialize, Serialize};

use crate::{CanonicalSkill, CsvRecord};

pub const SCHEMA_VERSION: u32 = 1;
/// Capture contract recorded in `RunRecord::harness_version` once every event
/// has an authoritative pre-detonation or detonation phase annotation.
pub const PHASE_CAPTURE_CONTRACT_VERSION: &str = "phase-v1";

pub const SKILLS_HEADERS: &[&str] = &[
    "schema_version",
    "skill_id",
    "sha256",
    "blake3",
    "canonicalization_version",
    "name",
    "publisher",
    "declared_version",
    "entrypoint",
    "license",
    "size_bytes",
    "file_count",
    "bundle_path",
    "manifest_path",
    "first_seen_at",
    "last_seen_at",
];

pub const DISCOVERIES_HEADERS: &[&str] = &[
    "schema_version",
    "discovery_id",
    "skill_id",
    "platform_id",
    "source_native_id",
    "source_url",
    "source_revision",
    "source_path",
    "etag",
    "publisher_display",
    "published_at",
    "first_seen_at",
    "last_seen_at",
    "ingest_run_id",
    "adapter_version",
];

pub const INGEST_REJECTIONS_HEADERS: &[&str] = &[
    "schema_version",
    "rejection_id",
    "platform_id",
    "source_url",
    "source_revision",
    "source_path",
    "reason",
    "first_seen_at",
    "last_seen_at",
    "adapter_version",
];

pub const PLATFORMS_HEADERS: &[&str] = &[
    "schema_version",
    "platform_id",
    "display_name",
    "canonical_domain",
    "base_url",
    "ingest_uri",
    "adapter",
    "status",
    "enabled",
    "discovery_method",
    "confidence",
    "first_seen_at",
    "last_seen_at",
    "rate_limit_per_minute",
    "terms_url",
    "evidence_url",
    "notes",
];

pub const RUNS_HEADERS: &[&str] = &[
    "schema_version",
    "run_id",
    "run_key",
    "skill_id",
    "status",
    "scenario",
    "seed",
    "queued_at",
    "started_at",
    "finished_at",
    "harness_version",
    "policy_sha256",
    "agent_adapter",
    "agent_model",
    "target_image_digest",
    "skillject_commit",
    "telemetry_path",
    "event_count",
    "exit_code",
    "termination_reason",
    "closure_lift_count",
    "taint_coverage",
];

pub const ASSESSMENTS_HEADERS: &[&str] = &[
    "schema_version",
    "assessment_id",
    "run_id",
    "skill_id",
    "verdict",
    "risk_score",
    "max_severity",
    "confidentiality_findings",
    "integrity_findings",
    "behavioral_findings",
    "unknown_platform_interaction",
    "unknown_platform_count",
    "coverage_state",
    "policy_version",
    "analyzer_version",
    "assessed_at",
];

pub const FINDINGS_HEADERS: &[&str] = &[
    "schema_version",
    "finding_id",
    "run_id",
    "rule_id",
    "category",
    "severity",
    "source_marker",
    "sink_kind",
    "sink_value",
    "evidence_seq_start",
    "evidence_seq_end",
    "summary",
];

pub const PLATFORM_EVIDENCE_HEADERS: &[&str] = &[
    "schema_version",
    "evidence_id",
    "platform_id",
    "run_id",
    "skill_id",
    "domain",
    "url",
    "evidence_kind",
    "event_seq",
    "confidence",
    "first_seen_at",
    "last_seen_at",
];

/// One immutable canonical skill bundle. Mutable discovery provenance lives in
/// [`DiscoveryRecord`] so the same content can be observed on many platforms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillRecord {
    pub schema_version: u32,
    pub skill_id: String,
    pub sha256: String,
    pub blake3: String,
    pub canonicalization_version: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub declared_version: Option<String>,
    #[serde(default)]
    pub entrypoint: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    pub size_bytes: u64,
    pub file_count: u64,
    pub bundle_path: String,
    pub manifest_path: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

impl SkillRecord {
    pub fn from_canonical(
        skill: &CanonicalSkill,
        bundle_path: impl Into<String>,
        manifest_path: impl Into<String>,
        observed_at: impl Into<String>,
    ) -> Self {
        let observed_at = observed_at.into();
        Self {
            schema_version: SCHEMA_VERSION,
            skill_id: skill.skill_id.clone(),
            sha256: skill.sha256.clone(),
            blake3: skill.blake3.clone(),
            canonicalization_version: skill.canonicalization_version,
            name: None,
            publisher: None,
            declared_version: None,
            entrypoint: None,
            license: None,
            size_bytes: skill.size_bytes,
            file_count: skill.file_count,
            bundle_path: bundle_path.into(),
            manifest_path: manifest_path.into(),
            first_seen_at: observed_at.clone(),
            last_seen_at: observed_at,
        }
    }
}

impl CsvRecord for SkillRecord {
    const HEADERS: &'static [&'static str] = SKILLS_HEADERS;

    fn stable_key(&self) -> &str {
        &self.skill_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryRecord {
    pub schema_version: u32,
    pub discovery_id: String,
    pub skill_id: String,
    pub platform_id: String,
    pub source_native_id: String,
    pub source_url: String,
    #[serde(default)]
    pub source_revision: Option<String>,
    #[serde(default)]
    pub source_path: Option<String>,
    #[serde(default)]
    pub etag: Option<String>,
    #[serde(default)]
    pub publisher_display: Option<String>,
    #[serde(default)]
    pub published_at: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub ingest_run_id: String,
    pub adapter_version: String,
}

impl CsvRecord for DiscoveryRecord {
    const HEADERS: &'static [&'static str] = DISCOVERIES_HEADERS;

    fn stable_key(&self) -> &str {
        &self.discovery_id
    }
}

/// One acquisition candidate that was safely rejected before canonicalization.
///
/// The identity includes the source revision and path, making the reason an
/// immutable audit fact for that exact candidate. Re-observations only widen
/// the first/last-seen interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestRejectionRecord {
    pub schema_version: u32,
    pub rejection_id: String,
    pub platform_id: String,
    pub source_url: String,
    pub source_revision: String,
    pub source_path: String,
    pub reason: String,
    pub first_seen_at: String,
    pub last_seen_at: String,
    pub adapter_version: String,
}

impl CsvRecord for IngestRejectionRecord {
    const HEADERS: &'static [&'static str] = INGEST_REJECTIONS_HEADERS;

    fn stable_key(&self) -> &str {
        &self.rejection_id
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformRecord {
    pub schema_version: u32,
    pub platform_id: String,
    pub display_name: String,
    pub canonical_domain: String,
    pub base_url: String,
    pub ingest_uri: String,
    pub adapter: String,
    pub status: String,
    pub enabled: bool,
    pub discovery_method: String,
    pub confidence: f64,
    #[serde(default)]
    pub first_seen_at: Option<String>,
    #[serde(default)]
    pub last_seen_at: Option<String>,
    #[serde(default)]
    pub rate_limit_per_minute: Option<u32>,
    #[serde(default)]
    pub terms_url: Option<String>,
    #[serde(default)]
    pub evidence_url: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl CsvRecord for PlatformRecord {
    const HEADERS: &'static [&'static str] = PLATFORMS_HEADERS;

    fn stable_key(&self) -> &str {
        &self.platform_id
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRecord {
    pub schema_version: u32,
    pub run_id: String,
    pub run_key: String,
    pub skill_id: String,
    pub status: String,
    pub scenario: String,
    pub seed: u64,
    pub queued_at: String,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
    pub harness_version: String,
    pub policy_sha256: String,
    pub agent_adapter: String,
    pub agent_model: String,
    pub target_image_digest: String,
    pub skillject_commit: String,
    #[serde(default)]
    pub telemetry_path: Option<String>,
    #[serde(default)]
    pub event_count: Option<u64>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub termination_reason: Option<String>,
    #[serde(default)]
    pub closure_lift_count: Option<u64>,
    #[serde(default)]
    pub taint_coverage: Option<f64>,
}

impl CsvRecord for RunRecord {
    const HEADERS: &'static [&'static str] = RUNS_HEADERS;

    fn stable_key(&self) -> &str {
        &self.run_id
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssessmentRecord {
    pub schema_version: u32,
    pub assessment_id: String,
    pub run_id: String,
    pub skill_id: String,
    pub verdict: String,
    pub risk_score: f64,
    pub max_severity: String,
    pub confidentiality_findings: u64,
    pub integrity_findings: u64,
    pub behavioral_findings: u64,
    /// True when this run interacted with a registered non-supported platform
    /// or emitted enough evidence to create a new platform candidate.
    #[serde(default)]
    pub unknown_platform_interaction: bool,
    /// Unique non-supported platform IDs observed in this run.
    #[serde(default)]
    pub unknown_platform_count: u64,
    pub coverage_state: String,
    pub policy_version: String,
    pub analyzer_version: String,
    pub assessed_at: String,
}

impl CsvRecord for AssessmentRecord {
    const HEADERS: &'static [&'static str] = ASSESSMENTS_HEADERS;

    fn stable_key(&self) -> &str {
        &self.assessment_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingRecord {
    pub schema_version: u32,
    pub finding_id: String,
    pub run_id: String,
    pub rule_id: String,
    pub category: String,
    pub severity: String,
    #[serde(default)]
    pub source_marker: Option<String>,
    pub sink_kind: String,
    pub sink_value: String,
    pub evidence_seq_start: u64,
    pub evidence_seq_end: u64,
    pub summary: String,
}

impl CsvRecord for FindingRecord {
    const HEADERS: &'static [&'static str] = FINDINGS_HEADERS;

    fn stable_key(&self) -> &str {
        &self.finding_id
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlatformEvidenceRecord {
    pub schema_version: u32,
    pub evidence_id: String,
    #[serde(default)]
    pub platform_id: Option<String>,
    pub run_id: String,
    pub skill_id: String,
    pub domain: String,
    pub url: String,
    pub evidence_kind: String,
    pub event_seq: u64,
    pub confidence: f64,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

impl CsvRecord for PlatformEvidenceRecord {
    const HEADERS: &'static [&'static str] = PLATFORM_EVIDENCE_HEADERS;

    fn stable_key(&self) -> &str {
        &self.evidence_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csv::WriterBuilder;

    fn serialized_headers<T: CsvRecord + Serialize>(sample: &T) -> Vec<String> {
        let mut writer = WriterBuilder::new().from_writer(Vec::new());
        writer.serialize(sample).unwrap();
        let data = writer.into_inner().unwrap();
        let mut reader = csv::Reader::from_reader(data.as_slice());
        reader
            .headers()
            .unwrap()
            .iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    #[test]
    fn serde_field_order_matches_every_schema_header() {
        let skill = SkillRecord {
            schema_version: 1,
            skill_id: "s".into(),
            sha256: "a".into(),
            blake3: "b".into(),
            canonicalization_version: 1,
            name: None,
            publisher: None,
            declared_version: None,
            entrypoint: None,
            license: None,
            size_bytes: 0,
            file_count: 0,
            bundle_path: "b".into(),
            manifest_path: "m".into(),
            first_seen_at: "t".into(),
            last_seen_at: "t".into(),
        };
        assert_eq!(serialized_headers(&skill), SKILLS_HEADERS);

        let discovery = DiscoveryRecord {
            schema_version: 1,
            discovery_id: "d".into(),
            skill_id: "s".into(),
            platform_id: "p".into(),
            source_native_id: "n".into(),
            source_url: "u".into(),
            source_revision: None,
            source_path: None,
            etag: None,
            publisher_display: None,
            published_at: None,
            first_seen_at: "t".into(),
            last_seen_at: "t".into(),
            ingest_run_id: "r".into(),
            adapter_version: "v".into(),
        };
        assert_eq!(serialized_headers(&discovery), DISCOVERIES_HEADERS);

        let rejection = IngestRejectionRecord {
            schema_version: 1,
            rejection_id: "reject".into(),
            platform_id: "p".into(),
            source_url: "u".into(),
            source_revision: "r".into(),
            source_path: "path".into(),
            reason: "unsafe path".into(),
            first_seen_at: "t".into(),
            last_seen_at: "t".into(),
            adapter_version: "v".into(),
        };
        assert_eq!(serialized_headers(&rejection), INGEST_REJECTIONS_HEADERS);

        let platform = PlatformRecord {
            schema_version: 1,
            platform_id: "p".into(),
            display_name: "p".into(),
            canonical_domain: "p.test".into(),
            base_url: "https://p.test".into(),
            ingest_uri: "https://p.test/repo".into(),
            adapter: "git".into(),
            status: "candidate".into(),
            enabled: false,
            discovery_method: "runtime".into(),
            confidence: 0.5,
            first_seen_at: None,
            last_seen_at: None,
            rate_limit_per_minute: None,
            terms_url: None,
            evidence_url: None,
            notes: None,
        };
        assert_eq!(serialized_headers(&platform), PLATFORMS_HEADERS);

        let run = RunRecord {
            schema_version: 1,
            run_id: "r".into(),
            run_key: "k".into(),
            skill_id: "s".into(),
            status: "queued".into(),
            scenario: "default".into(),
            seed: 1,
            queued_at: "t".into(),
            started_at: None,
            finished_at: None,
            harness_version: "v".into(),
            policy_sha256: "p".into(),
            agent_adapter: "a".into(),
            agent_model: "m".into(),
            target_image_digest: "i".into(),
            skillject_commit: "c".into(),
            telemetry_path: None,
            event_count: None,
            exit_code: None,
            termination_reason: None,
            closure_lift_count: None,
            taint_coverage: None,
        };
        assert_eq!(serialized_headers(&run), RUNS_HEADERS);

        let assessment = AssessmentRecord {
            schema_version: 1,
            assessment_id: "a".into(),
            run_id: "r".into(),
            skill_id: "s".into(),
            verdict: "benign".into(),
            risk_score: 0.0,
            max_severity: "none".into(),
            confidentiality_findings: 0,
            integrity_findings: 0,
            behavioral_findings: 0,
            unknown_platform_interaction: false,
            unknown_platform_count: 0,
            coverage_state: "complete".into(),
            policy_version: "v".into(),
            analyzer_version: "v".into(),
            assessed_at: "t".into(),
        };
        assert_eq!(serialized_headers(&assessment), ASSESSMENTS_HEADERS);

        let finding = FindingRecord {
            schema_version: 1,
            finding_id: "f".into(),
            run_id: "r".into(),
            rule_id: "rule".into(),
            category: "network".into(),
            severity: "low".into(),
            source_marker: None,
            sink_kind: "domain".into(),
            sink_value: "example.test".into(),
            evidence_seq_start: 1,
            evidence_seq_end: 2,
            summary: "summary".into(),
        };
        assert_eq!(serialized_headers(&finding), FINDINGS_HEADERS);

        let evidence = PlatformEvidenceRecord {
            schema_version: 1,
            evidence_id: "e".into(),
            platform_id: None,
            run_id: "r".into(),
            skill_id: "s".into(),
            domain: "example.test".into(),
            url: "https://example.test/s".into(),
            evidence_kind: "download".into(),
            event_seq: 1,
            confidence: 0.5,
            first_seen_at: "t".into(),
            last_seen_at: "t".into(),
        };
        assert_eq!(serialized_headers(&evidence), PLATFORM_EVIDENCE_HEADERS);
    }

    fn headers_from(data: &str) -> Vec<String> {
        csv::Reader::from_reader(data.as_bytes())
            .headers()
            .unwrap()
            .iter()
            .map(ToOwned::to_owned)
            .collect()
    }

    #[test]
    fn repository_ledgers_have_the_versioned_schemas_and_clawhub_seed() {
        assert_eq!(
            headers_from(include_str!("../../../data/skills.csv")),
            SKILLS_HEADERS
        );
        assert_eq!(
            headers_from(include_str!("../../../data/discoveries.csv")),
            DISCOVERIES_HEADERS
        );
        assert_eq!(
            headers_from(include_str!("../../../data/ingest_rejections.csv")),
            INGEST_REJECTIONS_HEADERS
        );
        assert_eq!(
            headers_from(include_str!("../../../data/runs.csv")),
            RUNS_HEADERS
        );
        assert_eq!(
            headers_from(include_str!("../../../data/assessments.csv")),
            ASSESSMENTS_HEADERS
        );
        assert_eq!(
            headers_from(include_str!("../../../data/findings.csv")),
            FINDINGS_HEADERS
        );
        assert_eq!(
            headers_from(include_str!("../../../data/platform_evidence.csv")),
            PLATFORM_EVIDENCE_HEADERS
        );

        let mut reader =
            csv::Reader::from_reader(include_str!("../../../data/platforms.csv").as_bytes());
        assert_eq!(
            reader.headers().unwrap().iter().collect::<Vec<_>>(),
            PLATFORMS_HEADERS
        );
        let platforms = reader
            .deserialize::<PlatformRecord>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let enabled_supported = platforms
            .iter()
            .filter(|platform| platform.enabled && platform.status == "supported")
            .collect::<Vec<_>>();
        assert_eq!(enabled_supported.len(), 1);
        let clawhub = enabled_supported[0];
        assert_eq!(clawhub.platform_id, "clawhub");
        assert_eq!(clawhub.ingest_uri, "https://clawhub.ai");
        assert_eq!(clawhub.adapter, "clawhub_api");
        assert_eq!(clawhub.status, "supported");
        assert!(clawhub.enabled);
        assert!(
            platforms
                .iter()
                .filter(|platform| platform.platform_id != "clawhub")
                .all(|platform| !platform.enabled && platform.status == "candidate")
        );
    }
}
