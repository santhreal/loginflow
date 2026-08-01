use assert_cmd::Command;

#[test]
fn cli_shows_help() {
    let mut cmd = Command::cargo_bin("loginflow").unwrap();
    cmd.arg("--help");
    cmd.assert().success();
}
