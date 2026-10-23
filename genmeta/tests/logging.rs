use std::process::{Command, Output};

fn run(args: &[&str], rust_log: &str) -> Output {
    let home = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_genmeta"))
        .args(args)
        .current_dir(home.path())
        .env("DHTTP_HOME", home.path())
        .env("RUST_LOG", rust_log)
        .output()
        .unwrap()
}

#[test]
fn ambient_rust_log_does_not_enable_runtime_logs_or_hide_command_errors() {
    for args in [
        vec!["nslookup", "localhost", "system", "--id", "missing"],
        vec!["curl", "https://example.com/", "--id", "missing"],
        vec!["proxy", "--id", "missing"],
        vec!["identity", "info", "missing"],
        vec!["access", "--id", "missing", "list"],
        vec!["install", "--list", "--id", "missing"],
        vec!["mount", "--id", "missing"],
    ] {
        let output = run(&args, "trace");
        assert!(!output.status.success(), "{args:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            !stderr.is_empty(),
            "{args:?}: command error must stay visible"
        );
        for level in ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"] {
            assert!(
                !stderr.contains(&format!(" {level} ")),
                "{args:?}: {stderr}"
            );
        }
    }
}

#[test]
fn explicit_debug_flag_enables_logs_even_when_rust_log_is_off() {
    for command in [
        vec!["nslookup", "localhost", "system", "--id", "missing"],
        vec!["curl", "https://example.com/", "--id", "missing"],
        vec!["proxy", "--id", "missing"],
    ] {
        for args in [
            [vec!["--verb"], command.clone()].concat(),
            [command.clone(), vec!["--verb"]].concat(),
        ] {
            let output = run(&args, "off");
            assert!(!output.status.success(), "{args:?}");
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains(" DEBUG "), "{args:?}: {stderr}");
        }
    }
}

#[test]
fn curl_verbose_output_does_not_enable_runtime_logs() {
    let output = run(
        &["curl", "-v", "https://example.com/", "--id", "missing"],
        "trace",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains(" DEBUG "), "{stderr}");
}
