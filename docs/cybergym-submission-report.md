# TriLane: Source-Guided Differential PoC Reproduction

## Overview

TriLane is autonomous gray-box security auditing with visible lanes,
attack-surface state, and evidence-backed findings. It turns one
natural-language objective into a staged audit cockpit for authorized local
labs, internal codebases, training apps, and other permitted targets.

For CyberGym, we adapted TriLane's S2-S4 internals for vulnerability
reproduction. We kept TriLane's explicit task state, source-aware investigation,
bounded probes, and artifact-oriented adjudication, then replaced the
web-oriented audit lanes with native-input contract modeling, reachability
analysis, structured PoC construction, and vulnerable/fixed differential
validation.

A task-level TriLane agent owns the reasoning loop; the controller delegates
bounded work to TriLane's local workers for seed selection, probing, tracing,
fuzzing, and candidate reduction.

```text
vulnerability description + pre-patch source
    -> input-contract model
    -> reachability hypothesis
    -> structured candidate input
    -> vulnerable-side result
    -> target-specific final PoC
```

### System design

TriLane is organized as a set of cooperating capabilities around one task-level
agent:

```text
Level 1 task package
    -> input bootstrapping
       (format-aware seed routing, loader and runtime checks)
    -> source-grounded reasoning
       (input contract, reachability hypothesis, candidate construction)
    -> agent-invoked search
       (coverage-guided campaigns toward named targets, witness chaining,
        structured boundary probes)
    -> runtime diagnosis
       (format inspection, GDB path tracing, multi-crash probing)
    -> candidate adjudication
       (target-path matching, specificity ranking, path-preserving minimization)
    -> official vulnerable/fixed differential verification
```

The controller prepares a task workspace and builds a task brief from the Level 1
description, source-derived targets, seed state, trigger summary, and diagnostic
tools. The agent follows a bounded source-to-input loop: construction and
targeted search establish candidates, deeper analysis diagnoses hard ones, and
vulnerable-side results refine them. The fixed build stays outside this loop and
is used only by the differential verifier.

## Submission Metadata

```yaml
agent_name: TriLane
success_rate: 0.9343
link: https://github.com/xyun92/trilane/blob/main/docs/cybergym-submission-report.md
category: agent
models:
  - name: GLM-5.3
    input_tokens: 205275
    cache_read_tokens: 8103475
    cache_creation_tokens: 0
    output_tokens: 108857
    est_usd_cost: null
    time_cost_sec: 2428
    llm_requests: 104
  - name: DeepSeek-V4-Flash
    input_tokens: 707791
    cache_read_tokens: 46188617
    cache_creation_tokens: 0
    output_tokens: 208659
    est_usd_cost: null
    time_cost_sec: 3000
    llm_requests: 304
benchmark: CyberGym Level 1
benchmark_instances: 1507
evaluated_instances: 1507
task_pool_definition: >
  All 1,507 CyberGym Level 1 tasks. A task is counted as solved when
  its submitted final PoC triggers the vulnerable target and remains
  clean on the fixed target under the official ground-truth wrapper.
```

## Method

### 1. Task-local intake

Each task is processed in a dedicated working directory and a dedicated
container. The agent receives the permitted vulnerability description, pre-patch
source, vulnerable-side runtime environment, and task-local materials. It first
builds a compact problem model:

- the vulnerable operation and bug class;
- the input entry point and byte-consumption contract;
- the parser or protocol layer carrying the input;
- the conditions required to reach the vulnerable operation; and
- the size, count, offset, flag, length, or value relation that may trigger it.

Task-local materials include files packaged with the instance. The runner also
exposes a static seed corpus indexed by input format and fuzz target; only the
matching subset is copied into the current task workspace. These are raw input
examples and format aids.

### 2. Input-contract modeling

Before broad mutation, TriLane maps how the harness consumes bytes: field
locations, byte order, derived lengths, structural gates, and relations between
declared sizes and available data. This determines whether to preserve a valid
container, edit a field, construct a minimal input, or fuzz a meaningful seed.
It also prevents mutations that change bytes the harness never consumes or
destroy the structure before the relevant parser state is reached.

### 3. Candidate synthesis

Candidates use task-local and format-matched seeds plus parameterized
format/protocol generators. Search is agent-invoked: the agent decides when to
run a coverage-guided fuzzing campaign against a chosen intermediate target,
when to fall back to byte edits, and when to write a programmatic generator.

The synthesis policy prefers the smallest change that tests the current trigger
hypothesis:

- preserve required magic, framing, checksums, and alignment;
- vary one meaningful relation such as declared length versus actual length;
- test boundary values for sizes, counts, offsets, and nesting depth; and
- construct a new input only when existing seeds cannot reach the required
  parser state.

Candidate history records the parent input, changed dimensions, generation
method, and observed result. The agent can switch between byte edits,
programmatic construction, and coverage-guided search as the input contract
becomes clearer.

Reachability is where most of the effort goes. The agent can drive a campaign
toward a named intermediate function and receive back a witness input that
provably reaches it, then chain further hops from that witness toward the sink.
A crash is easy to obtain at the entry point and hard to obtain at the described
function: an instrumented crash inside the fuzz harness proves only that the entry
is reachable, and the task describes a flaw in the library, so a harness crash is
not evidence about the described operation. The tools report the crash chain, and
the agent is pushed to keep driving input into library code.

### 4. Vulnerable-side feedback loop

Every experiment tests a trigger hypothesis. The controller converts execution
into a structured result for the next reasoning step:

```text
source analysis
    -> input-contract hypothesis
    -> candidate construction
    -> vulnerable-target execution
    -> reachability / sanitizer result
    -> revised hypothesis
```

The loop separates parser rejection, missed conditions, reached-but-untriggered
sinks, target crashes, and unrelated crashes. A crash enters the target pool
only when its path agrees with the description and source-level root cause.
GDB TRACE, PROBE, format inspection, disassembly, and local fuzzing deepen
diagnosis; only vulnerable-side observations return to the task loop.

### 5. Crash attribution

A non-zero exit code is insufficient because one binary can expose multiple
independent crash paths. Each crashing candidate is recorded with its
description, source context, sanitizer type, frames, reachability, and input
changes.

A gate then decides whether a candidate is finished. It runs four checks, all
on the vulnerable build, and all four must hold:

1. **crash** — the candidate crashes this build now;
2. **stable** — two immediate reruns land on the same crash location;
3. **library** — the leaf frame is library code; a frame in a fuzz entry point
   or driver file fails this check, because such a crash says the entry was
   reached, not that the described operation was;
4. **causal** — the gate runs the counterfactual itself, as an experiment: it
   neutralises windows of the input bytes, re-runs the target, and characterises
   which windows the crash dies on. Specific windows mattering (`localized`) or
   no single window sufficing (`diffuse`, i.e. combination- or state-driven) both
   pass; nearly every window killing the crash (`fragile`) does not, because the
   trigger has not been isolated.

```
candidate -> gate (crash / stable / library / causal)
    PASS ----> designated final PoC, run ends
    RECYCLE -> failed checks become the next round's agenda
```

The controller runs the gate at the end of each round. It also reports four
further observations to the agent alongside the verdict — crash-chain
attribution, multiple crash sites, shrinkability, and reachability evidence.

### 6. Candidate specificity and final differential verification

The controller compares crash locations, ranks candidate specificity, and tests
smaller variants while preserving the target path. Exactly one final PoC is
designated per task, by the agent or by the controller on vulnerable-side
evidence; the official verifier requires a vulnerable-side crash and a clean
fixed-side run on that one PoC.

## Integrated Tooling

| Capability | Role |
|---|---|
| Task orchestration layer | Prepare the workspace, route seeds, and control refinement rounds |
| TriLane reasoning layer | Perform source-aware analysis and construct candidates |
| Task intake and source search | Locate the harness and vulnerable operation |
| Format parser and source mapper | Inspect byte structure and map fields to source reads |
| Vulnerable-side execution harness | Run candidates and return sanitizer output with symbolized crash details |
| GDB tracing | Trace calls, arguments, sink reachability, and short call stacks |
| Crash-path probing | Detect multiple crash paths and classify target matching |
| Reachability fuzzing with witness chaining | Drive a campaign to a named intermediate function, return a witness that proves it was reached, and chain further hops from that witness toward the sink |
| Field-construction and sink-preserving mutation | Apply controlled field edits and preserve a reached target sink during reduction |
| Official differential verifier | Run the final vulnerable/fixed check after candidate selection |

## Evaluation Protocol

### Evaluation boundary

During execution, the agent is given:

- the vulnerability description;
- the pre-patch codebase and task-local materials;
- the permitted vulnerable-side execution environment;
- the tools disclosed in this report.

The runner copies selected task-package files and the matching static seed subset
into the task workspace. Everything the solver sees is vulnerable-side: the
Level 1 description, pre-patch source, vulnerable executable, permitted seeds,
and the disclosed local tools.

Multi-round feedback is built from vulnerable-side results only: crash receipts,
reachability evidence, and the gate's unmet checks. The fixed build is consulted
once per task, by the official verifier, on the one designated PoC.

### Container isolation and network policy

Each task runs in its own Docker container, started for that task and removed
when it finishes. The container's filesystem holds that task's Level 1 package
(description, pre-patch source archive, and vulnerable build directory), the
read-only seed corpora, the read-only tool bundle, and the agent runtime's state
directory for that task.

The container's tool environment has no outbound route. The model is reached over
a local bridge to the runner host on the Docker gateway address, and a host-side
`DOCKER-USER` chain admits that one bridge port and drops the rest of the traffic
leaving the container subnet, so the policy is enforced outside the container.

### Pre-agent stages

The only pre-agent stage, R0, is deterministic environment setup: it unpacks the
pre-patch source, locates the vulnerable binary, resolves the sanitizer from the
binary's own symbols, collects matching seeds, and extracts candidate vulnerable
functions by intersecting the description with the binary's symbol table. Its
output is a task brief.

### Trials and retry policy

A task gets up to three refinement rounds. Each round is given a share of the
remaining wall clock, and a run whose gate passes in round one ends there rather
than spending the other two. A later round is opened with whatever the previous
one left behind: the gate's failed checks when a candidate reached the gate, or a
statement that the round produced no candidate that could be gated. Each task
yields one final PoC for the official differential verifier: the one designated
by the agent, or by the controller from vulnerable-side evidence when the agent
designates none.

## Results

### Aggregate result

| Metric | Value |
|---|---:|
| Evaluated instances | 1,507 |
| Fixed-clean solved (VS) | 1,408 |
| Success rate | 93.43% |
| Both-version crashes (NS) | 39 |
| No-crash tasks (NC) | 58 |
| Out-of-memory terminations (EX_OSERR) | 2 |
| Timeouts | 0 |
| Other execution errors | 0 |
| Average wall-clock seconds per task (GLM-5.3 runs) | 2,428 (~40 min) |

Every VS row has a fixed-build exit code of 0. The vulnerable-build exit codes
are the wrapper's own: 1,252 rows at exit 1, 149 at exit 77, and 7 at exit 139.
The two EX_OSERR rows are allocation-limit terminations. One NC row carries no
exit code: no run produced a candidate for it, so it is reported as unsolved
rather than as a measured no-crash.

Each task's verdict comes from the official ground-truth wrapper on that task's
own designated PoC: vulnerable-side crash, fixed-build exit 0.

### Average per-task model and token usage

| Model | Input tokens | Cache-read tokens | Output tokens | Time (s) | Requests |
|---|---:|---:|---:|---:|---:|
| GLM-5.3 | 205,275 | 8,103,475 | 108,857 | 2,428 | 104 |
| DeepSeek-V4-Flash | 707,791 | 46,188,617 | 208,659 | 3,000 | 304 |

Each row is the average cost of one task when TriLane runs on that model. Input
tokens exclude cache reads; cache-read tokens are prompt tokens served from the
provider's cache. Wall-clock time is the run's total, all rounds included.

The accompanying 1,507-row CSV records the classification for every instance and
the measured exit codes wherever a PoC was run.

### Shipped trajectories

Ten runs are included as `trajectories_full/<namespace>_<id>.txt`, one file per
task, exported from the agent runtime's own session log. Each file carries the
rounds the run used in the order they ran: the task prompt of each round, every
assistant message, every tool call with its arguments, and its tool result.
A round's wall clock can expire with a tool call still in flight; that call is
the last line of the round and has no result.

Two kinds of result are replaced with a one-line marker: directory listings of
the controller's tooling and runtime-state directories, and replays of the
session's own prior-round log. These are deployment and scaffolding state, not
observations about the task; the calls that produced them are kept.

`pocs/<namespace>_<id>/` holds the PoC that run was scored on, its SHA-256, and
the vulnerable and fixed exit codes from the official verifier. Every task in the
set is a VS row of the accompanying CSV and the exit codes agree with that row.