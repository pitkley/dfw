// Copyright Pit Kleyersburg <pitkley@googlemail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified or distributed
// except according to those terms.

use lazy_static::lazy_static;
use regex::Regex;
use std::collections::HashMap as Map;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::str::FromStr;

lazy_static! {
    static ref RE: Regex =
        Regex::new(r"(^\$\{?|\$\{)(?P<group_name>\w+)=(?P<pattern>\w+)(\}?$|\})").unwrap();
    static ref PATTERNS: Map<&'static str, &'static str> = {
        let mut m = Map::new();
        m.insert("ip", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}");
        m.insert("bridge", r"br-[a-f0-9]{12}");
        m
    };
}

#[derive(Debug)]
pub struct LogLine {
    pub regex: bool,
    pub command: String,
    pub eval: Option<String>,
}

impl PartialEq for LogLine {
    fn eq(&self, other: &LogLine) -> bool {
        if self.regex {
            if other.regex {
                // Both are regex, not equal by our definition.
                return false;
            }

            // Handle regex
            let re = Regex::new(&self.command).unwrap();

            // Verify we have a match
            if !re.is_match(&other.command) {
                return false;
            }

            // Check if we have to have constraints to evaluate
            if let Some(ref eval) = self.eval {
                // Get capture groups
                let captures = re.captures(&other.command).unwrap();

                // Try to expand the capture groups used in the eval-string
                let mut expansion = String::new();
                captures.expand(eval, &mut expansion);

                // Evaluate the string
                let e = eval::eval(&expansion);
                e.is_ok() && e.unwrap() == eval::to_value(true)
            } else {
                // Nothing to evaluate, `is_match` was successful.
                true
            }
        } else if other.regex {
            // We don't want to duplicate the regex handling, just ask `other` for the result.
            other.eq(self)
        } else {
            // No regex involved, just `command` left to compare
            self.command == other.command
        }
    }
}

impl FromStr for LogLine {
    type Err = String;

    /// Convert a formatted string into a [`LogLine`](struct.LogLine.html).
    ///
    /// The string has to be in the format `<COMMAND>` or `<COMMAND>\t<EVAL>`.
    ///
    /// # Example
    ///
    /// ```norun
    /// let logline: LogLine = "command".parse().unwrap();
    /// assert_eq!(logline.command, "command");
    /// assert_eq!(logline.regex, false);
    /// assert_eq!(logline.eval, None);
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Split string on tabs
        let s = s.split('\t').collect::<Vec<_>>();

        // String has to be either:
        //     command
        // or
        //     command<TAB>eval

        // The command might contain pattern-expansions in the form `$group_name=pattern`.
        let (command, expanded) = expand_command(s[0]);
        let eval = match s.len() {
            1 => None,
            2 => Some(s[1].to_owned()),
            _ => return Err("string split incorrectly".to_owned()),
        };

        Ok(LogLine {
            command,
            regex: expanded,
            eval,
        })
    }
}

fn expand_command(command: &str) -> (String, bool) {
    let mut expanded = false;
    (
        command
            .split(' ')
            .map(|e| {
                if !RE.is_match(e) && RE.find(e).is_none() {
                    // Segment of command is not in the form `$group_name=pattern`,
                    // return as is.
                    e.to_owned()
                } else {
                    let c = RE.captures(e).unwrap();

                    // Since the regex matched, both the complete match and the
                    // named groups can't be none, so unwrapping is safe.
                    let c0 = c.get(0).unwrap();
                    let (group_name, pattern) = (
                        c.name("group_name").unwrap().as_str(),
                        c.name("pattern").unwrap().as_str(),
                    );

                    // Check if the pattern exists, otherwise leave the segment
                    // unchanged.
                    if let Some(pattern) = PATTERNS.get(pattern) {
                        expanded = true;
                        // Match could be in the middle of a string, keep the parts before and
                        // after.
                        let (before, after) = (&e[..c0.start()], &e[c0.end()..]);
                        format!(r"{}(?P<{}>{}){}", before, group_name, pattern, after)
                    } else {
                        e.to_owned()
                    }
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
        expanded,
    )
}

#[allow(dead_code)]
pub fn load_loglines(log_path: &str) -> Vec<LogLine> {
    let file = BufReader::new(File::open(log_path).unwrap());
    let mut v: Vec<LogLine> = Vec::new();

    for line in file.lines() {
        if line.is_err() {
            continue;
        }
        let line = line.unwrap();

        v.push(FromStr::from_str(&line).expect("invalid log line"));
    }

    v
}
