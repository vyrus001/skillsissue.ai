//! Shared, deterministic primitives for the SkillsIssue ingestion and analysis loops.
//!
//! The crate deliberately keeps repository state boring: versioned canonical skill
//! bundles, RFC 4180 CSV files, and a single advisory workspace lock.

pub mod canonical;
pub mod csv_store;
pub mod error;
pub mod id;
pub mod lock;
pub mod records;
pub mod time;

pub use canonical::{
    ArtifactValidationLimits, CANONICALIZATION_VERSION, CanonicalEntry, CanonicalSkill, EntryKind,
    Manifest, ManifestEntry, SkillArtifact, archive_skill_tree, canonicalize_skill_tree,
    validate_skill_artifact,
};
pub use csv_store::{
    CsvRecord, MergeStats, initialize_csv, merge_csv_records, read_csv_records,
    write_csv_records_atomic,
};
pub use error::{CoreError, Result};
pub use id::{detonation_shard_index, stable_id_v1};
pub use lock::WorkspaceLock;
pub use records::{
    ASSESSMENTS_HEADERS, AssessmentRecord, DISCOVERIES_HEADERS, DiscoveryRecord, FINDINGS_HEADERS,
    FindingRecord, INGEST_REJECTIONS_HEADERS, IngestRejectionRecord,
    PHASE_CAPTURE_CONTRACT_VERSION, PLATFORM_EVIDENCE_HEADERS, PLATFORMS_HEADERS,
    PlatformEvidenceRecord, PlatformRecord, RUNS_HEADERS, RunRecord, SCHEMA_VERSION,
    SKILLS_HEADERS, SkillRecord,
};
pub use time::{is_valid_utc_rfc3339, parse_utc_rfc3339, utc_now_rfc3339};
