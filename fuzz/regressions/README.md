# Kept fuzz findings

A finding the fuzzer saved is copied here as `<target>/<any name>.bin`, and
`cargo test -p rescue-core --features fuzzing` replays every file through the
same entry point on stable, in the ordinary test run. Keep the file even after
the fix: it is the regression test.
