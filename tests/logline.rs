extern crate eval;
extern crate regex;

mod logs;

use logs::*;

#[test]
fn string_eq_self() {
    let a = LogLine {
        function: "f".to_owned(),
        command: "c".to_owned(),
        regex: false,
        eval: None,
    };

    assert_eq!(a, a);
}

#[test]
fn string_eq_string() {
    let a = LogLine {
        function: "f".to_owned(),
        command: "c".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
        function: "f".to_owned(),
        command: "c".to_owned(),
        regex: false,
        eval: None,
    };

    assert_eq!(a, b);
    assert_eq!(b, a);
}

#[test]
fn string_ne_string() {
    let a = LogLine {
        function: "f1".to_owned(),
        command: "c".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
        function: "f2".to_owned(),
        command: "c".to_owned(),
        regex: false,
        eval: None,
    };

    assert_ne!(a, b);
    assert_ne!(b, a);

    let a = LogLine {
        function: "f".to_owned(),
        command: "c1".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
        function: "f".to_owned(),
        command: "c2".to_owned(),
        regex: false,
        eval: None,
    };

    assert_ne!(a, b);
    assert_ne!(b, a);
}

#[test]
fn string_eq_regex() {
    let a = LogLine {
        function: "f".to_owned(),
        command: "c a1b2c3d4".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
        function: "f".to_owned(),
        command: "c [a-d0-4]{8}".to_owned(),
        regex: true,
        eval: None,
    };

    assert_eq!(a, b);
    assert_eq!(b, a);
}

#[test]
fn string_ne_regex() {
    let a = LogLine {
        function: "f".to_owned(),
        command: "c e5f6g7h8".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
        function: "f".to_owned(),
        command: "c [a-d0-4]{8}".to_owned(),
        regex: true,
        eval: None,
    };

    assert_ne!(a, b);
    assert_ne!(b, a);
}

#[test]
fn regex_ne_self() {
    let a = LogLine {
        function: "f".to_owned(),
        command: "c".to_owned(),
        regex: true,
        eval: None,
    };

    assert_ne!(a, a);
}

#[test]
fn regex_ne_regex() {
    let a = LogLine {
        function: "f".to_owned(),
        command: "c".to_owned(),
        regex: true,
        eval: None,
    };
    let b = LogLine {
        function: "f".to_owned(),
        command: "c".to_owned(),
        regex: true,
        eval: None,
    };

    assert_ne!(a, b);
    assert_ne!(b, a);
}

#[test]
fn string_eq_regex_eval() {
    let a = LogLine {
        function: "f".to_owned(),
        command: "c a1b2c3d4 a1b2c3d4".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
        function: "f".to_owned(),
        command: "c (?P<group1>[a-d0-4]{8}) (?P<group2>[a-d0-4]{8})".to_owned(),
        regex: true,
        eval: Some(r#""$group1" == "$group2""#.to_owned()),
    };

    assert_eq!(a, b);
    assert_eq!(b, a);
}

#[test]
fn string_ne_regex_eval() {
    let a = LogLine {
        function: "f".to_owned(),
        command: "c a1b2c3d4 d4b3c2a1".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
        function: "f".to_owned(),
        command: "c (?P<group1>[a-d0-4]{8}) (?P<group2>[a-d0-4]{8})".to_owned(),
        regex: true,
        eval: Some(r#""$group1" == "$group2""#.to_owned()),
    };

    assert_ne!(a, b);
    assert_ne!(b, a);
}
