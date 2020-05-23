// Copyright Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

mod logs;

use logs::*;

#[test]
fn string_eq_self() {
    let a = LogLine {
        command: "c".to_owned(),
        regex: false,
        eval: None,
    };

    assert_eq!(a, a);
}

#[test]
fn string_eq_string() {
    let a = LogLine {
        command: "c".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
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
        command: "c1".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
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
        command: "c a1b2c3d4".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
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
        command: "c e5f6g7h8".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
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
        command: ("c".to_owned()),
        regex: true,
        eval: None,
    };

    assert_ne!(a, a);
}

#[test]
fn regex_ne_regex() {
    let a = LogLine {
        command: "c".to_owned(),
        regex: true,
        eval: None,
    };
    let b = LogLine {
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
        command: "c a1b2c3d4 a1b2c3d4".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
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
        command: "c a1b2c3d4 d4b3c2a1".to_owned(),
        regex: false,
        eval: None,
    };
    let b = LogLine {
        command: "c (?P<group1>[a-d0-4]{8}) (?P<group2>[a-d0-4]{8})".to_owned(),
        regex: true,
        eval: Some(r#""$group1" == "$group2""#.to_owned()),
    };

    assert_ne!(a, b);
    assert_ne!(b, a);
}

#[test]
fn logline_from_string() {
    let logline: LogLine = "command".parse().unwrap();
    assert_eq!(logline.command, "command".to_owned());
    assert_eq!(logline.regex, false);
    assert_eq!(logline.eval, None);
}

#[test]
fn logline_from_string_with_eval() {
    let logline: LogLine = "command\teval".parse().unwrap();
    assert_eq!(logline.command, "command".to_owned());
    assert_eq!(logline.regex, false);
    assert_eq!(logline.eval, Some("eval".to_owned()));
}

#[test]
fn logline_from_string_with_expansions() {
    let logline: LogLine = "$name=ip".parse().unwrap();
    assert_eq!(
        logline.command,
        r"(?P<name>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})".to_owned(),
    );
    assert_eq!(logline.regex, true);
    assert_eq!(logline.eval, None);

    let logline: LogLine = "$name=bridge".parse().unwrap();
    assert_eq!(logline.command, r"(?P<name>br-[a-f0-9]{12})".to_owned(),);
    assert_eq!(logline.regex, true);
    assert_eq!(logline.eval, None);
}

#[test]
fn logline_from_string_with_wrong_expansion() {
    let logline: LogLine = "$name=wrong".parse().unwrap();
    assert_eq!(logline.command, "$name=wrong".to_owned());
    assert_eq!(logline.regex, false);
    assert_eq!(logline.eval, None);
}

#[test]
fn logline_from_wrong_string() {
    let result: Result<LogLine, String> = "one\ttoo\tmany\ttabs".parse();
    assert!(result.is_err());
}
