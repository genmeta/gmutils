use std::process::{Command, Output};

fn run(args: &[&str], rust_log: &str) -> Output {
    let directory = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_jade"))
        .args(args)
        .current_dir(directory.path())
        .env("RUST_LOG", rust_log)
        .output()
        .unwrap()
}

#[test]
fn runtime_logs_require_the_explicit_debug_flag() {
    for command in [
        vec!["build", "missing-project-path"],
        vec!["publish", "missing.waz"],
    ] {
        let output = run(&command, "trace");
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.is_empty());
        for level in ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"] {
            assert!(!stderr.contains(&format!(" {level} ")), "{stderr}");
        }
        for args in [
            [vec!["--verb"], command.clone()].concat(),
            [command.clone(), vec!["--verb"]].concat(),
        ] {
            let output = run(&args, "off");
            assert!(!output.status.success());
            let stderr = String::from_utf8(output.stderr).unwrap();
            assert!(stderr.contains(" DEBUG "), "{args:?}: {stderr}");
        }
    }
}
