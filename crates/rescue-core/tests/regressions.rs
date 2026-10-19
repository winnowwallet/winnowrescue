//! Replays every fuzz finding kept under `fuzz/regressions/<target>/` through
//! the same entry point the fuzz target calls, on stable, in the ordinary test
//! run. A trap here fails the test process, which is the point.
#![cfg(feature = "fuzzing")]

use std::fs;
use std::path::Path;

fn replay(target: &str, data: &[u8]) {
    match target {
        "parse_secret" => rescue_core::fuzz_api::parse_secret(data),
        "parse_destination" => rescue_core::fuzz_api::parse_destination(data),
        "parse_path" => rescue_core::fuzz_api::parse_path(data),
        "parse_dumpwallet" => rescue_core::fuzz_api::parse_dumpwallet(data),
        other => panic!("no fuzz entry point named {other}"),
    }
}

#[test]
fn every_kept_finding_replays_without_a_trap() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/regressions");
    let Ok(targets) = fs::read_dir(&root) else {
        return;
    };
    for target in targets.flatten() {
        let name = target.file_name().to_string_lossy().into_owned();
        for case in fs::read_dir(target.path()).into_iter().flatten().flatten() {
            let data = fs::read(case.path()).expect("a kept finding is readable");
            replay(&name, &data);
        }
    }
}
