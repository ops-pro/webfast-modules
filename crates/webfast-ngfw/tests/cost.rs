//! What the built-in rules cost a clean request: the connection and head phases of every set
//! (`builtin: all`) over a browser's GET, counted by a global allocator that counts this thread's
//! allocations (docs/ngfw.md "Performance": a clean request allocates nothing on the rules' side).
//! The time of the same, in release, is printed by the ignored test:
//! `cargo test --release -p webfast-ngfw --test cost -- --ignored --nocapture`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::path::Path;
use std::time::Instant;
use webfast_ngfw::compile::{Compiled, compile};
use webfast_ngfw::config::{RulesConfig, compose};
use webfast_ngfw::engine::{Decision, Evaluation, Input};
use webfast_ngfw::rule::{Mode, Phase};

struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call is passed on to the system allocator as it came; the count is a
// const-initialised thread-local `Cell`, which allocates nothing.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: as the caller's contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as the caller's contract.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: as the caller's contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

fn builtin() -> Compiled {
    let (rules, _) = compose(&RulesConfig::default(), Path::new(".")).unwrap();
    compile(&rules, Mode::Block, &[]).unwrap()
}

/// A browser's GET of a page with a query and cookies.
fn clean_get() -> http::request::Parts {
    http::Request::get("/en/products/shoes?q=running+shoes&page=2&sort=price")
        .header("host", "www.example.com")
        .header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        )
        .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("accept-language", "en-US,en;q=0.9")
        .header("accept-encoding", "gzip, deflate, br")
        .header("referer", "https://www.example.com/en/")
        .header("cookie", "session=4f2a9c0e7b1d; theme=dark; consent=1")
        .body(())
        .unwrap()
        .into_parts()
        .0
}

fn head(compiled: &Compiled, parts: &http::request::Parts) -> Decision {
    let input = Input {
        parts,
        client_ip: "203.0.113.7".parse().unwrap(),
        country: Some(*b"NL"),
        asn: Some(1136),
        sni: Some("www.example.com"),
        ja4: None,
        body: None,
        response: None,
        hidden: &[],
    };
    let mut evaluation = Evaluation::new();
    evaluation.run_phase(compiled, Phase::Connection, &input, 200);
    evaluation.run_phase(compiled, Phase::Head, &input, 200);
    assert!(evaluation.hits.is_empty(), "a clean GET matched a rule");
    evaluation.decision(5)
}

#[test]
fn a_clean_get_allocates_nothing_in_the_built_in_rules() {
    let compiled = builtin();
    let parts = clean_get();
    // The thread's buffers grow on the first request; after it, nothing.
    assert_eq!(head(&compiled, &parts), Decision::Continue);
    let before = allocations();
    for _ in 0..100 {
        assert_eq!(head(&compiled, &parts), Decision::Continue);
    }
    assert_eq!(allocations() - before, 0, "allocations on a clean GET");
}

#[test]
#[ignore]
fn the_head_phase_of_a_clean_get_costs() {
    let compiled = builtin();
    let parts = clean_get();
    head(&compiled, &parts);
    let mut best = f64::MAX;
    for _ in 0..5 {
        let n = 200_000;
        let start = Instant::now();
        for _ in 0..n {
            std::hint::black_box(head(&compiled, std::hint::black_box(&parts)));
        }
        best = best.min(start.elapsed().as_nanos() as f64 / n as f64);
    }
    println!(
        "{} rules: the connection and head phases of a clean GET, best of 5: {best:.0} ns",
        compiled.rules.len()
    );
}
