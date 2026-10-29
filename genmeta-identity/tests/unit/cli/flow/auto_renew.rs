use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use dhttp_home::{DhttpHome, HomeScope};
use dhttp_identity::name::DhttpName;

use super::{
    build_entry, disable_identity, enable_identity, ensure_with, is_identity_enabled,
    scheduled_executable, updated_crontab,
};

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("genmeta-auto-renew-{}-{nonce}", std::process::id()))
}

#[test]
fn preserves_a_stable_symlink_from_the_invocation_path() {
    let test_dir = unique_test_dir();
    let cellar_dir = test_dir.join("Cellar/gmutils/0.5.0/bin");
    let stable_bin_dir = test_dir.join("bin");
    std::fs::create_dir_all(&cellar_dir).unwrap();
    std::fs::create_dir_all(&stable_bin_dir).unwrap();
    let versioned_executable = cellar_dir.join("genmeta");
    std::fs::write(&versioned_executable, b"test executable").unwrap();
    let stable_executable = stable_bin_dir.join("genmeta");
    std::os::unix::fs::symlink(&versioned_executable, &stable_executable).unwrap();

    let resolved = scheduled_executable(
        &versioned_executable,
        Some(std::ffi::OsStr::new("genmeta")),
        Some(stable_bin_dir.as_os_str()),
        None,
    );

    assert_eq!(resolved, stable_executable);
    std::fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn absolutizes_a_stable_symlink_found_through_a_relative_path_entry() {
    let test_dir = unique_test_dir();
    let versioned_dir = test_dir.join("Cellar/gmutils/0.5.0/bin");
    let stable_dir = test_dir.join("bin");
    std::fs::create_dir_all(&versioned_dir).unwrap();
    std::fs::create_dir_all(&stable_dir).unwrap();
    let versioned_executable = versioned_dir.join("genmeta");
    std::fs::write(&versioned_executable, b"test executable").unwrap();
    let stable_executable = stable_dir.join("genmeta");
    std::os::unix::fs::symlink(&versioned_executable, &stable_executable).unwrap();

    let resolved = scheduled_executable(
        &versioned_executable,
        Some(std::ffi::OsStr::new("genmeta")),
        Some(std::ffi::OsStr::new("bin")),
        Some(&test_dir),
    );

    assert_eq!(resolved, stable_executable);
    assert!(resolved.is_absolute());
    std::fs::remove_dir_all(test_dir).unwrap();
}

#[test]
fn builds_scope_aware_commands_for_launcher_and_standalone_binaries() {
    let (user_entry, _) =
        build_entry(Path::new("/opt/Genmeta Tools/genmeta"), HomeScope::User).unwrap();
    let (global_entry, _) = build_entry(
        Path::new("/usr/local/bin/genmeta-identity"),
        HomeScope::Global,
    )
    .unwrap();

    assert_eq!(
        user_entry,
        "0 3 * * * '/opt/Genmeta Tools/genmeta' 'identity' 'renew' '--all' >/dev/null 2>&1 # genmeta-auto-renew:user"
    );
    assert_eq!(
        global_entry,
        "0 3 * * * '/usr/local/bin/genmeta-identity' '--global' 'renew' '--all' >/dev/null 2>&1 # genmeta-auto-renew:global"
    );
}

#[test]
fn repeated_registration_does_not_rewrite_or_duplicate_the_entry() {
    let (entry, marker) = build_entry(Path::new("/usr/bin/genmeta"), HomeScope::User).unwrap();
    let existing = format!("MAILTO=ops@example.test\n{entry}\n");

    assert_eq!(updated_crontab(&existing, &entry, &marker), None);
}

#[test]
fn stale_and_duplicate_aggregate_entries_collapse_to_one() {
    let (entry, marker) = build_entry(Path::new("/usr/bin/genmeta"), HomeScope::User).unwrap();
    let existing = format!(
        "15 1 * * * /usr/bin/backup\n0 2 * * * /old/genmeta identity renew --all {marker}\n{entry}\n{entry}\n"
    );

    let updated = updated_crontab(&existing, &entry, &marker).unwrap();
    assert_eq!(updated.matches(&marker).count(), 1);
    assert_eq!(updated.matches(&entry).count(), 1);
    assert!(updated.contains("15 1 * * * /usr/bin/backup"));
}

#[test]
fn other_scope_and_unmanaged_entries_are_preserved() {
    let (entry, marker) = build_entry(Path::new("/usr/bin/genmeta"), HomeScope::User).unwrap();
    let unmanaged = "0 3 * * * /usr/bin/backup";
    let global =
        "0 3 * * * /usr/bin/genmeta identity --global renew --all # genmeta-auto-renew:global";
    let existing = format!("{unmanaged}\n{global}\n");

    let updated = updated_crontab(&existing, &entry, &marker).unwrap();
    assert!(updated.contains(unmanaged));
    assert!(updated.contains(global));
    assert_eq!(updated.matches("genmeta-auto-renew").count(), 2);
}

#[tokio::test]
async fn command_round_trip_installs_idempotently_through_crontab_interface() {
    let test_dir = unique_test_dir();
    let crontab = test_dir.join("crontab");
    let state = test_dir.join("state");
    let update_count = test_dir.join("update-count");
    tokio::fs::create_dir_all(&test_dir).await.unwrap();
    let script = format!(
        "#!/bin/sh\ncase \"$1\" in\n  -l)\n    if [ -f \"{}\" ]; then cat \"{}\"; else echo 'no crontab for test' >&2; exit 1; fi\n    ;;\n  -)\n    cat > \"{}\"\n    printf x >> \"{}\"\n    ;;\n  *) exit 2 ;;\nesac\n",
        state.display(),
        state.display(),
        state.display(),
        update_count.display(),
    );
    tokio::fs::write(&crontab, script).await.unwrap();
    let mut permissions = tokio::fs::metadata(&crontab).await.unwrap().permissions();
    permissions.set_mode(0o700);
    tokio::fs::set_permissions(&crontab, permissions)
        .await
        .unwrap();

    for _ in 0..2 {
        ensure_with(&crontab, Path::new("/usr/bin/genmeta"), HomeScope::User)
            .await
            .unwrap();
    }

    let installed = tokio::fs::read_to_string(&state).await.unwrap();
    assert_eq!(installed.matches("genmeta-auto-renew").count(), 1);
    assert_eq!(tokio::fs::read_to_string(&update_count).await.unwrap(), "x");
    tokio::fs::remove_dir_all(test_dir).await.unwrap();
}

#[tokio::test]
async fn identity_disable_state_round_trips_with_the_terminal_reason() {
    let test_dir = unique_test_dir();
    let dhttp_home = DhttpHome::new(test_dir.clone());
    let identity = DhttpName::try_from("alice.smith").unwrap();
    tokio::fs::create_dir_all(
        dhttp_home
            .identity_profile((identity.borrow()).as_full())
            .expect("validated identity name")
            .path(),
    )
    .await
    .unwrap();

    assert!(
        is_identity_enabled(&dhttp_home, identity.borrow())
            .await
            .unwrap()
    );
    disable_identity(&dhttp_home, identity.borrow(), "domain_expired")
        .await
        .unwrap();
    assert!(
        !is_identity_enabled(&dhttp_home, identity.borrow())
            .await
            .unwrap()
    );
    assert_eq!(
        tokio::fs::read_to_string(test_dir.join("alice.smith/.auto-renew-disabled"))
            .await
            .unwrap(),
        "domain_expired\n"
    );

    enable_identity(&dhttp_home, identity.borrow())
        .await
        .unwrap();
    enable_identity(&dhttp_home, identity.borrow())
        .await
        .unwrap();
    assert!(
        is_identity_enabled(&dhttp_home, identity.borrow())
            .await
            .unwrap()
    );
    tokio::fs::remove_dir_all(test_dir).await.unwrap();
}
