extern crate assert_cmd;
extern crate predicates;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_create_account() -> Result<(), Box<dyn std::error::Error>> {
    create_account("test_user1", "test_password").unwrap();
    delete_account("test_user1", "test_password").unwrap();

    Ok(())
}

fn create_account(name: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("idvault")?;

    cmd.arg("account")
        .arg("add")
        .arg("-u")
        .arg(name)
        .arg("-p")
        .arg(password)
        .arg("-x")
        .arg("test_export_key");

    cmd.assert().success();

    Ok(())
}

fn delete_account(name: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("idvault")?;

    cmd.arg("account")
        .arg("delete")
        .arg("-f")
        .arg("-u")
        .arg(name)
        .arg("-p")
        .arg(password);

    cmd.assert().success();

    Ok(())
}
