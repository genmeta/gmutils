use super::*;

#[test]
fn package_labels_preserve_the_actual_author() {
    for (canonical, displayed) in [
        (
            "dev.genmeta.tech.dhttp.net/workspace",
            "dev.genmeta.tech~/workspace",
        ),
        ("std.dhttp.net/workspace", "std/workspace"),
        ("alice.smith.dhttp.net/hello", "alice.smith~/hello"),
    ] {
        assert_eq!(package_id(canonical), displayed);
    }
}
