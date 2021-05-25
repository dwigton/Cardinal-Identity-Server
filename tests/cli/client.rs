extern crate assert_cmd;
extern crate predicates;
use crate::cli::client::assert_cmd::prelude::*;
use std::process::Command;
use crate::cli::account::{create_account, delete_account};
use crate::cli::application::{create_application, delete_application, add_scopes, delete_scopes};

#[test]
fn test_create_client() {
    create_account("client_user1", "client_email01@example.com", "test_password");
    create_application("client_user1", "test_password", "spout1", "Spout", "https://spout.example.com");

    add_scopes(
        "client_user1",
        "test_password",
        "spout1",
        &["crap", "regurgitate", "admire", "flush"],
        &["smell"]
        );

    create_client("client_user1", "test_password", "spout1", &["crap", "admire"], &["smell"]);

    delete_scopes(
        "client_user1",
        "test_password",
        "spout1",
        &["crap", "regurgitate", "admire", "flush"],
        &["smell"]
        );

    delete_application("client_user1", "test_password", "spout1");
    delete_account("client_user1", "test_password");
}

pub fn create_client(account: &str, password: &str, code: &str, write_scopes: &[&str], read_scopes: &[&str]) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("client")
        .arg("add")
        .arg("-a")
        .arg(account)
        .arg("-p")
        .arg(password)
        .arg("-c")
        .arg(code);

    for write_scope in write_scopes {
        cmd.arg("-w").arg(write_scope);
    }

    for read_scope in read_scopes {
        cmd.arg("-r").arg(read_scope);
    }

    cmd.assert().success();
}

pub fn revoke_client(account: &str, password: &str, code: &str, write_scopes: &[&str], read_scopes: &[&str]) {
    let mut cmd = Command::cargo_bin("idvault").unwrap();

    cmd.arg("client")
        .arg("revoke")
        .arg("-a")
        .arg(account)
        .arg("-p")
        .arg(password)
        .arg("-c")
        .arg(code);

    for write_scope in write_scopes {
        cmd.arg("-w").arg(write_scope);
    }

    for read_scope in read_scopes {
        cmd.arg("-r").arg(read_scope);
    }

    cmd.assert().success();
}
