extern crate dfw;

use dfw::iptables::{IPTables, IPTablesLogger};

#[test]
fn log_all() {
    let ipt = IPTablesLogger::new();

    ipt.get_policy("table", "chain").unwrap();
    ipt.set_policy("table", "chain", "policy").unwrap();
    ipt.execute("table", "command").unwrap();
    ipt.exists("table", "chain", "rule").unwrap();
    ipt.chain_exists("table", "chain").unwrap();
    ipt.insert("table", "chain", "rule", 0).unwrap();
    ipt.insert_unique("table", "chain", "rule", 0).unwrap();
    ipt.replace("table", "chain", "rule", 0).unwrap();
    ipt.append("table", "chain", "rule").unwrap();
    ipt.append_unique("table", "chain", "rule").unwrap();
    ipt.append_replace("table", "chain", "rule").unwrap();
    ipt.delete("table", "chain", "rule").unwrap();
    ipt.delete_all("table", "chain", "rule").unwrap();
    ipt.list("table", "chain").unwrap();
    ipt.list_table("table").unwrap();
    ipt.list_chains("table").unwrap();
    ipt.new_chain("table", "chain").unwrap();
    ipt.flush_chain("table", "chain").unwrap();
    ipt.rename_chain("table", "old_chain", "new_chain").unwrap();
    ipt.delete_chain("table", "chain").unwrap();
    ipt.flush_table("table").unwrap();

    let logs = ipt.logs();

    let expected = vec![("get_policy", "table chain"),
                        ("set_policy", "table chain policy"),
                        ("execute", "table command"),
                        ("exists", "table chain rule"),
                        ("chain_exists", "table chain"),
                        ("insert", "table chain rule 0"),
                        ("insert_unique", "table chain rule 0"),
                        ("replace", "table chain rule 0"),
                        ("append", "table chain rule"),
                        ("append_unique", "table chain rule"),
                        ("append_replace", "table chain rule"),
                        ("delete", "table chain rule"),
                        ("delete_all", "table chain rule"),
                        ("list", "table chain"),
                        ("list_table", "table"),
                        ("list_chains", "table"),
                        ("new_chain", "table chain"),
                        ("flush_chain", "table chain"),
                        ("rename_chain", "table old_chain new_chain"),
                        ("delete_chain", "table chain"),
                        ("flush_table", "table")]
            .into_iter()
            .map(|(a, b)| (a.to_owned(), b.to_owned()))
            .collect::<Vec<_>>();

    assert_eq!(logs, expected);
}
