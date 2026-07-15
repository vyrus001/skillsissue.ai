use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use csv::{ReaderBuilder, StringRecord, Terminator, WriterBuilder};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{CoreError, Result};

/// A repository CSV row with an explicit schema and deterministic primary key.
pub trait CsvRecord: Serialize + DeserializeOwned + Clone {
    const HEADERS: &'static [&'static str];

    fn stable_key(&self) -> &str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeStats {
    pub existing: usize,
    pub incoming: usize,
    pub inserted: usize,
    pub replaced: usize,
    pub total: usize,
}

/// Create a header-only RFC 4180 file when it does not yet exist.
///
/// Returns `true` when a file was created. An existing file is schema-checked.
pub fn initialize_csv<T: CsvRecord>(path: impl AsRef<Path>) -> Result<bool> {
    let path = path.as_ref();
    if path.exists() {
        let _ = read_csv_records::<T>(path)?;
        return Ok(false);
    }
    write_csv_records_atomic::<T, _>(path, std::iter::empty())?;
    Ok(true)
}

/// Read and strictly schema-check a typed repository CSV.
pub fn read_csv_records<T: CsvRecord>(path: impl AsRef<Path>) -> Result<Vec<T>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path).map_err(|error| CoreError::io(path, error))?;
    let mut reader = ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(file);
    let actual = reader
        .headers()
        .map_err(|source| CoreError::Csv {
            path: path.to_owned(),
            source,
        })?
        .clone();
    verify_headers::<T>(path, &actual)?;

    reader
        .deserialize()
        .collect::<std::result::Result<Vec<T>, csv::Error>>()
        .map_err(|source| CoreError::Csv {
            path: path.to_owned(),
            source,
        })
}

/// Atomically replace a CSV with records sorted lexicographically by primary key.
///
/// Duplicate keys in `records` are rejected. Writers that may run concurrently
/// should hold a [`crate::WorkspaceLock`] for the surrounding read/modify/write.
pub fn write_csv_records_atomic<T, I>(path: impl AsRef<Path>, records: I) -> Result<usize>
where
    T: CsvRecord,
    I: IntoIterator<Item = T>,
{
    let path = path.as_ref();
    let mut ordered = BTreeMap::new();
    for record in records {
        let key = checked_key(&record)?;
        if ordered.insert(key.clone(), record).is_some() {
            return Err(CoreError::DuplicateStableKey(key));
        }
    }
    write_ordered(path, ordered.values())?;
    Ok(ordered.len())
}

/// Merge incoming rows by primary key, replacing prior rows and writing a stable order.
///
/// Incoming duplicate keys are rejected. The operation uses a same-directory temporary
/// file and atomic rename. Hold a [`crate::WorkspaceLock`] to prevent lost updates across
/// independent processes.
pub fn merge_csv_records<T, I>(path: impl AsRef<Path>, incoming: I) -> Result<MergeStats>
where
    T: CsvRecord,
    I: IntoIterator<Item = T>,
{
    let path = path.as_ref();
    let existing_records = read_csv_records::<T>(path)?;
    let existing = existing_records.len();
    let mut ordered = BTreeMap::new();
    for record in existing_records {
        let key = checked_key(&record)?;
        if ordered.insert(key.clone(), record).is_some() {
            return Err(CoreError::DuplicateStableKey(key));
        }
    }

    let mut incoming_keys = BTreeMap::<String, ()>::new();
    let mut inserted = 0;
    let mut replaced = 0;
    for record in incoming {
        let key = checked_key(&record)?;
        if incoming_keys.insert(key.clone(), ()).is_some() {
            return Err(CoreError::DuplicateStableKey(key));
        }
        if ordered.insert(key, record).is_some() {
            replaced += 1;
        } else {
            inserted += 1;
        }
    }

    let incoming = inserted + replaced;
    write_ordered(path, ordered.values())?;
    Ok(MergeStats {
        existing,
        incoming,
        inserted,
        replaced,
        total: ordered.len(),
    })
}

fn checked_key<T: CsvRecord>(record: &T) -> Result<String> {
    let key = record.stable_key();
    if key.is_empty() {
        return Err(CoreError::EmptyStableKey);
    }
    Ok(key.to_owned())
}

fn verify_headers<T: CsvRecord>(path: &Path, actual: &StringRecord) -> Result<()> {
    if actual.iter().eq(T::HEADERS.iter().copied()) {
        return Ok(());
    }
    Err(CoreError::HeaderMismatch {
        path: path.to_owned(),
        expected: T::HEADERS.iter().map(|value| (*value).to_owned()).collect(),
        actual: actual.iter().map(ToOwned::to_owned).collect(),
    })
}

fn write_ordered<'a, T, I>(path: &Path, records: I) -> Result<()>
where
    T: CsvRecord + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| CoreError::io(parent, error))?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).map_err(|error| CoreError::io(parent, error))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map(|metadata| metadata.permissions().mode())
            .unwrap_or(0o644);
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| CoreError::io(temporary.path(), error))?;
    }

    {
        let mut writer = WriterBuilder::new()
            .has_headers(false)
            .terminator(Terminator::CRLF)
            .from_writer(temporary.as_file_mut());
        writer
            .write_record(T::HEADERS)
            .map_err(|source| CoreError::Csv {
                path: path.to_owned(),
                source,
            })?;
        for record in records {
            writer.serialize(record).map_err(|source| CoreError::Csv {
                path: path.to_owned(),
                source,
            })?;
        }
        writer.flush().map_err(|error| CoreError::io(path, error))?;
    }
    temporary
        .as_file_mut()
        .flush()
        .map_err(|error| CoreError::io(temporary.path(), error))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| CoreError::io(temporary.path(), error))?;

    temporary.persist(path).map_err(|error| CoreError::Io {
        path: path.to_owned(),
        source: error.error,
    })?;
    sync_parent(parent)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| CoreError::io(parent, error))
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Row {
        id: String,
        value: String,
    }

    impl CsvRecord for Row {
        const HEADERS: &'static [&'static str] = &["id", "value"];

        fn stable_key(&self) -> &str {
            &self.id
        }
    }

    fn row(id: &str, value: &str) -> Row {
        Row {
            id: id.into(),
            value: value.into(),
        }
    }

    #[test]
    fn initializes_header_only_file_and_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.csv");
        assert!(initialize_csv::<Row>(&path).unwrap());
        assert!(!initialize_csv::<Row>(&path).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"id,value\r\n");
        assert!(read_csv_records::<Row>(&path).unwrap().is_empty());
    }

    #[test]
    fn merge_replaces_by_key_and_writes_stable_rfc4180() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.csv");
        write_csv_records_atomic(&path, [row("z", "old"), row("a", "plain")]).unwrap();
        let stats =
            merge_csv_records(&path, [row("z", "new, quoted"), row("m", "two\nlines")]).unwrap();
        assert_eq!(
            stats,
            MergeStats {
                existing: 2,
                incoming: 2,
                inserted: 1,
                replaced: 1,
                total: 3,
            }
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "id,value\r\na,plain\r\nm,\"two\nlines\"\r\nz,\"new, quoted\"\r\n"
        );
        assert_eq!(
            read_csv_records::<Row>(&path).unwrap(),
            [
                row("a", "plain"),
                row("m", "two\nlines"),
                row("z", "new, quoted")
            ]
        );
    }

    #[test]
    fn rejects_schema_drift() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.csv");
        fs::write(&path, b"value,id\r\nx,a\r\n").unwrap();
        assert!(matches!(
            read_csv_records::<Row>(&path),
            Err(CoreError::HeaderMismatch { .. })
        ));
    }

    #[test]
    fn rejects_empty_and_duplicate_keys_without_replacing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.csv");
        write_csv_records_atomic(&path, [row("a", "kept")]).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(matches!(
            merge_csv_records(&path, [row("b", "one"), row("b", "two")]),
            Err(CoreError::DuplicateStableKey(key)) if key == "b"
        ));
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(matches!(
            merge_csv_records(&path, [row("", "bad")]),
            Err(CoreError::EmptyStableKey)
        ));
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}
