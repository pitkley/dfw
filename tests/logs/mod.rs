use eval;
use regex::Regex;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;

#[derive(Debug)]
pub struct LogLine {
    pub function: String,
    pub regex: bool,
    pub command: String,
    pub eval: Option<String>,
}

impl PartialEq for LogLine {
    fn eq(&self, other: &LogLine) -> bool {
        // If `function` is unequal, we don't have to do further comparisons
        if self.function != other.function {
            return false;
        }

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
                captures.expand(&eval, &mut expansion);

                // Evaluate the string
                let e = eval::eval(&expansion);
                return e.is_ok() && e.unwrap() == eval::to_value(true);
            } else {
                // Nothing to evaluate, `is_match` was successful.
                return true;
            }
        } else {
            if other.regex {
                // We don't want to duplicate the regex handling, just ask `other` for the result.
                return other.eq(self);
            } else {
                // No regex involved, just `command` left to compare
                return self.command == other.command;
            }
        }
    }
}

pub fn load_log(log_path: &str) -> Vec<LogLine> {
    let file = BufReader::new(File::open(log_path).unwrap());
    let mut v = Vec::new();

    for line in file.lines() {
        if line.is_err() {
            continue;
        }
        let line = line.unwrap();

        let s = line.split("\t").collect::<Vec<_>>();
        v.push(match s.len() {
                   2 => {
                       LogLine {
                           function: s[0].to_owned(),
                           command: s[1].to_owned(),
                           regex: false,
                           eval: None,
                       }
                   }
                   3 => {
                       LogLine {
                           function: s[0].to_owned(),
                           command: s[1].to_owned(),
                           regex: true,
                           eval: Some(s[2].to_owned()),
                       }
                   }
                   _ => panic!("log line split incorrectly"),
               });
    }

    v
}
