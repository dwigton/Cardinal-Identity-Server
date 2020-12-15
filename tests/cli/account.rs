extern crate assert_cmd;
extern crate predicates;
use crate::cli::account::assert_cmd::prelude::*;
use std::process::Command;
use std::panic;

#[test]
fn test_create_account() {
    create_account("test_user1", "test_password");
    delete_account("test_user1", "test_password");
}

#[test]
fn test_change_account_password() {

    create_account("test_user2", "test_password");

    let mut cmd = Command::cargo_bin("idvault").unwrap();

    // Change the password
    cmd.arg("account")
        .arg("chngpwd")
        .arg("-a")
        .arg("test_user2")
        .arg("-p")
        .arg("test_password")
        .arg("-r")
        .arg("new_password");

    cmd.assert().success();

    // Delete with old password, should fail

    let result = panic::catch_unwind(|| {
        delete_account("test_user2", "test_password");
    });

    match result {
        Ok(_) => panic!("No error when using old password."),
        Err(_) => {},
    }

    delete_account("test_user2", "new_password");
}

pub fn create_account(name: &str, password: &str) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("account")
        .arg("add")
        .arg("-a")
        .arg(name)
        .arg("-p")
        .arg(password)
        .arg("-x")
        .arg("test_export_key");

    cmd.assert().success();
}

pub fn delete_account(name: &str, password: &str) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("account")
        .arg("delete")
        .arg("-f")
        .arg("-a")
        .arg(name)
        .arg("-p")
        .arg(password);

    cmd.assert().success();
}
