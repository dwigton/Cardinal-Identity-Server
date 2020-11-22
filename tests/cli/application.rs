extern crate assert_cmd;
extern crate predicates;
use cli::application::assert_cmd::prelude::*;
use cli::application::predicates::prelude::*;
use std::process::Command;
use std::panic;
use cli::account::{create_account, delete_account};

#[test]
fn test_create_application() {
    create_account("application_user1", "test_password");
    create_application("spout", "application_user1", "test_password");
    delete_application("spout", "application_user1", "test_password");
    delete_account("application_user1", "test_password");
}

#[test]
fn test_change_account_password() {

    create_account("application_user2", "test_password");

    let mut cmd = Command::cargo_bin("idvault").unwrap();

    // Change the password
    cmd.arg("account")
        .arg("chngpwd")
        .arg("-u")
        .arg("application_user2")
        .arg("-p")
        .arg("test_password")
        .arg("-r")
        .arg("new_password");

    cmd.assert().success();

    // Delete with old password, should fail

    let result = panic::catch_unwind(|| {
        delete_account("application_user2", "test_password");
    });

    match result {
        Ok(_) => panic!("No error when using old password."),
        Err(_) => {},
    }

    delete_account("application_user2", "new_password");
}

fn create_application(code: &str, name: &str, password: &str) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("account")
        .arg("add")
        .arg("-u")
        .arg(name)
        .arg("-p")
        .arg(password)
        .arg("-x")
        .arg("test_export_key");

    cmd.assert().success();
}

fn delete_application(code: &str, name: &str, password: &str) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("account")
        .arg("delete")
        .arg("-f")
        .arg("-u")
        .arg(name)
        .arg("-p")
        .arg(password);

    cmd.assert().success();
}
