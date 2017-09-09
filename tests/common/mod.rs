use std::path::PathBuf;

pub fn resource(segment: &str) -> Option<String> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("resources/test");
    p.push(segment);

    p.to_str().map(|s| s.to_owned())
}
