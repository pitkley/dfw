extern crate dfw;

use dfw::iptables::*;

#[test]
fn dummy_get_policy() {
    let ipt = IPTablesDummy;

    let result = ipt.get_policy("", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "");
}

#[test]
fn dummy_set_policy() {
    let ipt = IPTablesDummy;

    let result = ipt.set_policy("", "", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_execute() {
    let ipt = IPTablesDummy;

    let result = ipt.execute("", "");
    assert!(result.is_ok());
    let output = result.unwrap();
    assert_eq!(output.status.success(), false);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn dummy_exists() {
    let ipt = IPTablesDummy;

    let result = ipt.exists("", "", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_chain_exists() {
    let ipt = IPTablesDummy;

    let result = ipt.chain_exists("", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_insert() {
    let ipt = IPTablesDummy;

    let result = ipt.insert("", "", "", 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_insert_unique() {
    let ipt = IPTablesDummy;

    let result = ipt.insert_unique("", "", "", 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_replace() {
    let ipt = IPTablesDummy;

    let result = ipt.replace("", "", "", 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_append() {
    let ipt = IPTablesDummy;

    let result = ipt.append("", "", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_append_unique() {
    let ipt = IPTablesDummy;

    let result = ipt.append_unique("", "", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_append_replace() {
    let ipt = IPTablesDummy;

    let result = ipt.append_replace("", "", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_delete() {
    let ipt = IPTablesDummy;

    let result = ipt.delete("", "", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_delete_all() {
    let ipt = IPTablesDummy;

    let result = ipt.delete_all("", "", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_list() {
    let ipt = IPTablesDummy;

    let result = ipt.list("", "");
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn dummy_list_table() {
    let ipt = IPTablesDummy;

    let result = ipt.list_table("");
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn dummy_list_chains() {
    let ipt = IPTablesDummy;

    let result = ipt.list_chains("");
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn dummy_new_chain() {
    let ipt = IPTablesDummy;

    let result = ipt.new_chain("", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_flush_chain() {
    let ipt = IPTablesDummy;

    let result = ipt.flush_chain("", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_rename_chain() {
    let ipt = IPTablesDummy;

    let result = ipt.rename_chain("", "", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_delete_chain() {
    let ipt = IPTablesDummy;

    let result = ipt.delete_chain("", "");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}

#[test]
fn dummy_flush_table() {
    let ipt = IPTablesDummy;

    let result = ipt.flush_table("");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), false);
}
