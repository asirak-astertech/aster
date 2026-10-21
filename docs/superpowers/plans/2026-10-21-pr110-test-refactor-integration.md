# PR #110 Test-Refactor Integration Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update PR #110 onto current `main`, preserving both semantic-v9 Blob streaming and the merged resource-bounded test pipeline.

**Architecture:** Merge current `main` once so the 98 signed feature commits remain intact, then resolve overlapping source and test surfaces by retaining both numbered Event publication and Blob-stream profile 5. Regenerate API artifacts from the merged schema rather than hand-merging generated output.

**Tech Stack:** Rust 1.97.1/1.91 MSRV, Tokio, ConnectRPC/Protobuf, Go bindings, cargo-nextest, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-20-fast-resource-bounded-tests-design.md`; `docs/superpowers/specs/2026-10-19-aster-data-mesh-streaming-dag-design.md`

## Global Constraints

- Preserve semantic-v7/v8 compatibility and semantic-v9/profile-5 fail-closed selection.
- Preserve numbered-only Event publication introduced on current `main`.
- Keep correctness fixtures bounded; scale/performance evidence stays in explicit qualification lanes.
- Do not broaden PR #110 into profile-5 lifecycle quota/reclamation work.
- Every new integration commit must be signed.

## Review Focus

- Generated ConnectRPC and descriptor artifacts must exactly match the merged protobuf schema.
- Numbered Event publication APIs must coexist with resumable Blob publication/status APIs.
- Refactored test fixtures must retain Blob stream boundary, cancellation, and resume assertions.
- CI lane classification must not silently omit profile-5 protocol coverage.
- macOS and Linux fixtures must keep platform-neutral request and cleanup behavior.

---

### Task 1: Integrate current main

**Files:**
- Modify: merge-conflicted source, test, schema, and generated API files reported by `git merge-tree`

**Interfaces:**
- Consumes: current PR #110 head and `canonical/main`
- Produces: one resolved merge worktree containing both feature sets

- [x] Merge `canonical/main` without committing.
- [x] Classify each conflict as schema/generated, agent/CLI API, runtime, or test fixture.
- [x] Resolve source/schema conflicts while preserving both capabilities.
- [x] Regenerate generated artifacts from the resolved schema.

### Task 2: Validate the combined behavior

**Files:**
- Test: focused packages and test lanes selected from the touched conflict set

**Interfaces:**
- Consumes: resolved integration tree
- Produces: formatting, compilation, protocol, numbered-publication, and Blob-stream evidence

- [x] Run formatting and diff checks.
- [x] Run focused schema/generation checks.
- [x] Run focused numbered-publication and Blob-stream tests.
- [x] Run strict Clippy for touched Rust packages.

### Task 3: Publish and validate CI

**Files:**
- Modify: PR #110 branch and evidence text only if counts or commands changed

**Interfaces:**
- Consumes: verified integration tree
- Produces: signed merge commit, updated fork branch, and green current-base CI

- [x] Create and verify one signed merge commit.
- [x] Push once to the fork branch.
- [ ] Wait for all required checks and fix concrete failures without running the full local suite.
- [ ] Confirm clean merge state, signatures, and current-main ancestry.

### Task 4: Close the completed-contact admission gap

**Files:**
- Modify: `crates/aster-node/src/runtime.rs`

**Interfaces:**
- Consumes: issue #116's completed-but-uncollected inbound worker state
- Produces: generation-safe same-peer admission without allowing live overlap

- [x] Reproduce active versus completed-uncollected worker state deterministically.
- [x] Reject a genuinely active same-peer worker while allowing its completed predecessor to be replaced.
- [x] Keep an older completion from clearing the replacement worker's peer ownership.
- [x] Run the focused regression plus strict formatting, compilation, and Clippy checks.
