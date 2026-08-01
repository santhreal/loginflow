use assert_cmd::Command;

#[test]
fn cli_fails_on_missing_args() {
    let mut cmd = Command::cargo_bin("loginflow").unwrap();
    cmd.arg("login");
    cmd.assert().failure();
}
