//! `central-runsubmit` — Phase 2 run submission orchestration over
//! `central-task` + `central-workflow` change sets (approved DAG edges);
//! every task transition passes through `central-task` (issue-122).
//!
//! The port of `internal/runsubmit/runsubmit.go`: [`domain`] carries the
//! constants, request bounds, fixed task-input marker, and child-spec
//! batches; [`app`] carries the [`app::Service`] saga behind
//! `central run submit` and `POST /app/runs/submit`.

pub mod app;
pub mod domain;
