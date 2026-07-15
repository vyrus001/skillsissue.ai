use sha2::{Digest, Sha256};

const ID_DOMAIN: &[u8] = b"skillsissue.id\0v1\0";
const DETONATION_SHARD_DOMAIN: &[u8] = b"skillsissue-detonation-shard-v1\0";

/// Derive a deterministic, domain-separated identifier from byte-string parts.
///
/// The result is formatted as `<namespace>:v1:<sha256-hex>`. Each input is framed
/// by its unsigned 64-bit big-endian length, so adjoining fields cannot collide.
pub fn stable_id_v1<I, B>(namespace: &str, parts: I) -> String
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut hash = Sha256::new();
    hash.update(ID_DOMAIN);
    update_frame(&mut hash, namespace.as_bytes());
    for part in parts {
        update_frame(&mut hash, part.as_ref());
    }
    format!("{namespace}:v1:{}", hex::encode(hash.finalize()))
}

/// Assign an immutable skill ID to a stable zero-based detonation shard.
///
/// Returns `None` for a zero shard count. The assignment deliberately excludes
/// mutable policy and image state so one dispatcher matrix remains disjoint
/// even when workers resolve their runtime configuration independently.
pub fn detonation_shard_index(skill_id: &str, shard_count: u32) -> Option<u32> {
    if shard_count == 0 {
        return None;
    }
    let mut hash = blake3::Hasher::new();
    hash.update(DETONATION_SHARD_DOMAIN);
    hash.update(&(skill_id.len() as u64).to_le_bytes());
    hash.update(skill_id.as_bytes());
    let prefix = hash.finalize().as_bytes()[..8]
        .try_into()
        .expect("BLAKE3 digests are at least eight bytes");
    Some((u64::from_le_bytes(prefix) % u64::from(shard_count)) as u32)
}

fn update_frame(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_stable_and_framed() {
        let left = stable_id_v1("run", [b"ab".as_slice(), b"c".as_slice()]);
        let right = stable_id_v1("run", [b"a".as_slice(), b"bc".as_slice()]);
        assert_ne!(left, right);
        assert_eq!(
            left,
            stable_id_v1("run", [b"ab".as_slice(), b"c".as_slice()])
        );
        assert!(left.starts_with("run:v1:"));
        assert_eq!(left.len(), "run:v1:".len() + 64);
    }

    #[test]
    fn namespace_is_part_of_the_domain() {
        assert_ne!(
            stable_id_v1("run", [b"same".as_slice()]),
            stable_id_v1("finding", [b"same".as_slice()])
        );
    }

    #[test]
    fn detonation_shards_are_stable_and_validate_count() {
        assert_eq!(detonation_shard_index("sha256:v1:alpha", 8), Some(4));
        assert_eq!(detonation_shard_index("sha256:v1:beta", 8), Some(2));
        assert_eq!(detonation_shard_index("sha256:v1:alpha", 1), Some(0));
        assert_eq!(detonation_shard_index("sha256:v1:alpha", 0), None);
    }
}
