//! Narrow persistence adapter around `skills-core`.

use std::path::Path;

use anyhow::Result;
use skills_core::{merge_csv_records, read_csv_records, write_csv_records_atomic, CsvRecord};

use crate::model::{AssessmentRecord, PlatformRecord, RunRecord};

pub fn read_runs(path: &Path) -> Result<Vec<RunRecord>> {
    Ok(read_csv_records(path)?)
}

pub fn read_assessments(path: &Path) -> Result<Vec<AssessmentRecord>> {
    Ok(read_csv_records(path)?)
}

pub fn read_platforms(path: &Path) -> Result<Vec<PlatformRecord>> {
    Ok(read_csv_records(path)?)
}

pub fn merge_records<T>(path: &Path, incoming: Vec<T>) -> Result<()>
where
    T: CsvRecord,
{
    merge_csv_records(path, incoming)?;
    Ok(())
}

pub fn write_records_atomic<T, I>(path: &Path, records: I) -> Result<()>
where
    T: CsvRecord,
    I: IntoIterator<Item = T>,
{
    write_csv_records_atomic(path, records)?;
    Ok(())
}
