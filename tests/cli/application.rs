extern crate assert_cmd;
extern crate predicates;
use cli::application::assert_cmd::prelude::*;
use std::process::Command;
use cli::account::{create_account, delete_account};

#[test]
fn test_create_application() {
    create_account("application_user1", "test_password");
    create_application("application_user1", "test_password", "spout1", "Spout", "https://spout.example.com");
    delete_application("application_user1", "test_password", "spout1");
    delete_account("application_user1", "test_password");
}

#[test]
fn test_add_remove_scopes() {
    create_account("application_user2", "test_password");
    create_application("application_user2", "test_password", "spout1", "Spout", "https://spout.example.com");

    add_scopes(
        "application_user2",
        "test_password",
        "spout1",
        &["crap", "regurgitate", "admire", "flush"],
        &["smell"]
        );

    delete_scopes(
        "application_user2",
        "test_password",
        "spout1",
        &["crap", "regurgitate", "admire", "flush"],
        &["smell"]
        );

    delete_application("application_user2", "test_password", "spout1");
    delete_account("application_user2", "test_password");
}

pub fn create_application(account: &str, password: &str, code: &str, description: &str, url: &str) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("application")
        .arg("add")
        .arg("-u")
        .arg(account)
        .arg("-p")
        .arg(password)
        .arg("-c")
        .arg(code)
        .arg("-d")
        .arg(description)
        .arg("--url")
        .arg(url);

    cmd.assert().success();
}

pub fn delete_application(account: &str, password: &str, code: &str) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("application")
        .arg("delete")
        .arg("-f")
        .arg("-c")
        .arg(code)
        .arg("-u")
        .arg(account)
        .arg("-p")
        .arg(password);

    cmd.assert().success();
}

pub fn add_scopes(account: &str, password: &str, application_code: &str, write_scopes: &[&str], read_scopes: &[&str]) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("application")
        .arg("scope")
        .arg("-u")
        .arg(account)
        .arg("-p")
        .arg(password)
        .arg("-c")
        .arg(application_code);

    for write_scope in write_scopes {
        cmd.arg("-w").arg(write_scope);
    }

    for read_scope in read_scopes {
        cmd.arg("-r").arg(read_scope);
    }

    cmd.assert().success();
}

pub fn delete_scopes(account: &str, password: &str, application_code: &str, write_scopes: &[&str], read_scopes: &[&str]) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("application")
        .arg("scope")
        .arg("-u")
        .arg(account)
        .arg("-p")
        .arg(password)
        .arg("-c")
        .arg(application_code)
        .arg("-d")
        .arg("-f");

    for write_scope in write_scopes {
        cmd.arg("-w").arg(write_scope);
    }

    for read_scope in read_scopes {
        cmd.arg("-r").arg(read_scope);
    }

    cmd.assert().success();
}
