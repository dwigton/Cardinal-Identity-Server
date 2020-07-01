use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn create_account() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("idvault")?;

    cmd.arg("account")
        .arg("add")
        .arg("-u")
        .arg("test_user")
        .arg("-p")
        .arg("test_password")
        .arg("-x")
        .arg("test_export_key");

    cmd.assert().success();

    Ok(())
}
