use std::path::PathBuf;

/// Errors returned by shared SkillsIssue storage and canonicalization operations.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("CSV error at {path}: {source}")]
    Csv {
        path: PathBuf,
        #[source]
        source: csv::Error,
    },

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("skill root is not a real directory: {0}")]
    InvalidRoot(PathBuf),

    #[error("unsafe path {path}: {reason}")]
    UnsafePath { path: PathBuf, reason: String },

    #[error(
        "unsupported filesystem node at {0}; only directories, regular files, and safe relative symlinks are allowed"
    )]
    UnsupportedFileType(PathBuf),

    #[error("CSV header mismatch at {path}: expected {expected:?}, found {actual:?}")]
    HeaderMismatch {
        path: PathBuf,
        expected: Vec<String>,
        actual: Vec<String>,
    },

    #[error("CSV record has an empty stable key")]
    EmptyStableKey,

    #[error("duplicate CSV stable key: {0}")]
    DuplicateStableKey(String),

    #[error("workspace is already locked: {0}")]
    LockContended(PathBuf),

    #[error("timestamp is not UTC RFC3339: {0}")]
    InvalidTimestamp(String),

    #[error("skill tree changed while it was being archived")]
    TreeChanged,

    #[error("invalid skill artifact at {path}: {reason}")]
    InvalidArtifact { path: PathBuf, reason: String },
}

impl CoreError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;
