use super::*;

#[test]
fn inventory_is_sorted_and_identity_is_independent_of_creation_order_and_root() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    for name in ["b.img", "a.img"] { fs::write(first.path().join(name), name).unwrap(); }
    for name in ["a.img", "b.img"] { fs::write(second.path().join(name), name).unwrap(); }
    assert_eq!(inspect(first.path(), 10).unwrap(), inspect(second.path(), 10).unwrap());
    let inventory = Inventory::read(first.path(), Limits::new(10)).unwrap();
    assert_eq!(inventory.entries[0].relative, Path::new("a.img"));
}

#[test]
fn paths_contents_lengths_and_empty_directories_all_bind_the_digest() {
    let original = tempfile::tempdir().unwrap();
    fs::write(original.path().join("a"), b"1234").unwrap();
    let baseline = inspect(original.path(), 10).unwrap().0;
    for (name, bytes, directory) in [
        ("b", b"1234".as_slice(), false),
        ("a", b"4321".as_slice(), false),
        ("a", b"123".as_slice(), false),
        ("a", b"1234".as_slice(), true),
    ] {
        let candidate = tempfile::tempdir().unwrap();
        fs::write(candidate.path().join(name), bytes).unwrap();
        if directory { fs::create_dir(candidate.path().join("empty")).unwrap(); }
        assert_ne!(baseline, inspect(candidate.path(), 10).unwrap().0);
    }
}

#[test]
fn byte_limit_is_exact_and_sparse_oversize_is_refused_before_reading() {
    let dir = tempfile::tempdir().unwrap();
    let file = File::create(dir.path().join("sparse.img")).unwrap();
    file.set_len(4).unwrap();
    assert_eq!(inspect(dir.path(), 4).unwrap().1, 4);
    file.set_len(u64::from(u32::MAX) + 1).unwrap();
    assert!(matches!(inspect(dir.path(), 4), Err(LinuxMigrationError::SnapshotTooLarge { .. })));
}

#[test]
fn entry_depth_and_path_budgets_include_empty_directories() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("a/b")).unwrap();
    let base = Limits::new(0);
    for limits in [
        Limits { entries: 1, ..base },
        Limits { depth: 1, ..base },
        Limits { path_bytes: 2, ..base },
        Limits { total_path_bytes: 3, ..base },
    ] {
        assert!(matches!(Inventory::read(dir.path(), limits),
            Err(LinuxMigrationError::SnapshotStructureLimit { .. })));
    }
    assert!(Inventory::read(dir.path(), Limits {
        entries: 2, depth: 2, path_bytes: 3, total_path_bytes: 4, ..base
    }).is_ok());
}

#[test]
fn file_growth_and_shrink_between_inventory_and_read_are_rejected() {
    for replacement in [b"longer".as_slice(), b"a".as_slice()] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.img"), b"abc").unwrap();
        let inventory = Inventory::read(dir.path(), Limits::new(20)).unwrap();
        fs::write(dir.path().join("a.img"), replacement).unwrap();
        assert!(matches!(digest(dir.path(), &inventory), Err(LinuxMigrationError::SnapshotChanged { .. })));
    }
}

#[test]
fn new_entries_after_inventory_cannot_be_silently_omitted() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits::new(10);
    let inventory = Inventory::read(dir.path(), limits).unwrap();
    fs::write(dir.path().join("late.img"), b"late").unwrap();
    assert!(matches!(inventory.ensure_unchanged(dir.path(), limits),
        Err(LinuxMigrationError::SnapshotChanged { .. })));
}

#[test]
fn streaming_never_buffers_a_whole_image_and_matches_canonical_framing() {
    let dir = tempfile::tempdir().unwrap();
    let data = vec![0x5a; BUFFER_BYTES * 3 + 7];
    fs::write(dir.path().join("core.img"), &data).unwrap();
    let inventory = Inventory::read(dir.path(), Limits::new(data.len() as u64)).unwrap();
    let mut buffer = [0_u8; 31];
    let mut calls = 0;
    let mut total = 0;
    stream_file(dir.path(), &inventory.entries[0], &mut buffer, |bytes| {
        assert!(bytes.len() <= 31);
        assert!(bytes.iter().all(|byte| *byte == 0x5a));
        total += bytes.len(); calls += 1; Ok(())
    }).unwrap();
    assert_eq!(total, data.len());
    assert!(calls > 3);
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&1_u64.to_le_bytes());
    hasher.update(&[1]);
    hasher.update(&8_u64.to_le_bytes());
    hasher.update(b"core.img");
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(&data);
    assert_eq!(inspect(dir.path(), data.len() as u64).unwrap().0,
        ObjectId::from_unscoped_bytes(hasher.finalize().as_bytes()));
}

#[test]
fn consumer_failure_stops_streaming_immediately() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.img"), [7_u8; 100]).unwrap();
    let inventory = Inventory::read(dir.path(), Limits::new(100)).unwrap();
    let mut calls = 0;
    let result = stream_file(dir.path(), &inventory.entries[0], &mut [0_u8; 10], |_| {
        calls += 1;
        Err(io::Error::other("destination full"))
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
}

#[cfg(unix)]
#[test]
fn symlink_roots_nested_links_and_special_files_are_refused() {
    use std::os::unix::{fs::symlink, net::UnixListener};
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(matches!(inspect(&link, 100), Err(LinuxMigrationError::UnsupportedSnapshotEntry { .. })));
    assert!(matches!(inspect(dir.path(), 100), Err(LinuxMigrationError::UnsupportedSnapshotEntry { .. })));
    let other = tempfile::tempdir().unwrap();
    let _socket = UnixListener::bind(other.path().join("socket")).unwrap();
    assert!(matches!(inspect(other.path(), 100), Err(LinuxMigrationError::UnsupportedSnapshotEntry { .. })));
}

#[cfg(unix)]
#[test]
fn replaced_leaf_symlink_is_not_opened_after_inventory() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("a.img");
    fs::write(&image, b"image").unwrap();
    let inventory = Inventory::read(dir.path(), Limits::new(100)).unwrap();
    fs::rename(&image, dir.path().join("old.img")).unwrap();
    symlink("old.img", &image).unwrap();
    assert!(digest(dir.path(), &inventory).is_err());
}
