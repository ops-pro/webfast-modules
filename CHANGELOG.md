# Changelog

## Unreleased

- The NGFW request filter (`webfast-ngfw`) and the browser challenge (`webfast-challenge`),
  moved out of the webfast repository as crates on `webfast-core`'s module API; the code, rules,
  documentation and tests as they were there, unreleased. The request filter's `challenge` feature
  (on by default) is its dependency on the challenge crate; the tests boot the core's harness with
  a composition of the crate under test.
- maxminddb 0.27 (RUSTSEC advisory on 0.26's `Reader::open_mmap`, which the filter does not call;
  the lookup API changed: `lookup(ip)?.decode()`).
