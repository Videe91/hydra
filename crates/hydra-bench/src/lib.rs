//! # hydra-bench
//!
//! Criterion baselines for the Hydra engine and storage hot paths.
//!
//! No library API — this crate exists solely to host
//! `benches/engine.rs` and `benches/storage.rs`. Run with:
//!
//! ```sh
//! cargo bench -p hydra-bench
//! ```
//!
//! Criterion writes HTML reports under `target/criterion/` (the
//! `html_reports` feature is on by default). No CI regression
//! thresholds are wired yet — this patch is baseline numbers only.
