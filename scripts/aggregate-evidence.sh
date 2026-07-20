#!/usr/bin/env bash
# aggregate-evidence.sh — evidence reducer for the kvm-microvm-orchestrator plan.
#
# Plan todo 33: "Aggregate evidence and enforce deterministic/privileged/benchmark
# outcome semantics." This tool is the evidence reducer that todo 33 calls for
# (the plan references it as `evidence-reduce`); the task instruction reconciles
# its output path to `.omo/evidence/kvm-microvm-orchestrator/summary.json`.
#
# What it does
#   1. Verifies every plan todo (1..34) has an evidence file that parses as JSON.
#   2. Classifies each todo into one of four lanes: deterministic | privileged |
#      benchmark | meta (environment / schema / aggregation / release tasks).
#   3. Extracts a lane-aware outcome from each evidence file using the project's
#      fail-closed outcome vocabulary (schemas/README.md):
#        - deterministic : pass | fail            (there is NO blocked state)
#        - privileged    : pass | blocked | fail  (anti-mock: no pass without real substrate)
#        - benchmark     : published | blocked | fail (anti-boolean: NEVER a pass field)
#        - meta          : pass | blocked | fail
#   4. Validates the dedicated lane artifacts against their JSON schemas' fail-closed
#      invariants (class discriminator, additionalProperties, anti-mock, anti-boolean,
#      summary arithmetic) using jq (no external schema dependency is available).
#   5. Emits a unified verification matrix at summary.json.
#
# Fail-closed guarantees (the whole point of todo 33)
#   * Blocked evidence is NEVER erased: an explicit blocked signal always yields a
#     blocked outcome; a privileged todo is only `pass` when affirmative real-substrate
#     proof is present, otherwise it is reported blocked (never promoted to pass).
#   * Passes are NEVER fabricated: a privileged `pass` requires real_boot/real-run
#     proof; a benchmark never records `pass` (it records published distributions).
#   * A missing evidence artifact is a failure (todo 33 acceptance: "missing artifact
#     is a failure") and, in strict mode, makes the reducer exit non-zero.
#
# Usage
#   scripts/aggregate-evidence.sh [--root DIR] [--out FILE] [--require-complete] [--allow-incomplete]
#
# Exit codes
#   0  aggregation succeeded and (in --allow-incomplete mode) missing todos are tolerated
#   1  integrity failure: an evidence file is invalid JSON, a benchmark carries a `pass`
#      field, a deterministic todo reports blocked, summary arithmetic does not
#      reconcile, or (default strict mode) a todo has no evidence artifact.
#
# This script is read-only with respect to evidence: it never modifies or deletes an
# evidence file. It only writes the summary report (--out).

set -uo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PLAN="kvm-microvm-orchestrator"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_ROOT="$REPO_ROOT/.omo/evidence/$PLAN"
OUT="$EVIDENCE_ROOT/summary.json"
FIRST_TODO=1
LAST_TODO=34
# Default: strict. A missing artifact is a failure (todo 33 acceptance). Use
# --allow-incomplete for a mid-plan progress view that tolerates missing todos.
REQUIRE_COMPLETE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) EVIDENCE_ROOT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --require-complete) REQUIRE_COMPLETE=1; shift ;;
    --allow-incomplete) REQUIRE_COMPLETE=0; shift ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Lane map: todo -> lane.
#
# Derived from schemas/README.md lane definitions and each todo's verification
# character in .omo/plans/kvm-microvm-orchestrator.md:
#   deterministic : reproducible across hosts; no /dev/kvm, /dev/net/tun, or cgroup
#                   mutation (types, state machine, policy, contract, path/digest
#                   validation, transport parity, scheduler pure logic, OCI importer,
#                   CLI, snapshot manifest, direct-KVM contract docs, operator docs).
#   privileged    : exercises real /dev/kvm, /dev/net/tun, cgroup-v2 mutation,
#                   Firecracker/jailer, TAP/netns, snapshot/restore against real KVM.
#   benchmark     : latency distributions + Docker cold/warm comparison + warm HTTP demo.
#   meta          : environment bootstrap, evidence-schema definition, this aggregation,
#                   and the release-readiness matrix (not a test-lane artifact).
# ---------------------------------------------------------------------------
lane_for() {
  case "$1" in
    1|2|33|34) echo meta ;;
    27|28) echo benchmark ;;
    4|10|11|12|13|14|15|19|22|23|30|31) echo privileged ;;
    3|5|6|7|8|9|16|17|18|20|21|24|25|26|29|32) echo deterministic ;;
    *) echo "UNKNOWN" ;;
  esac
}

# Evidence file that carries the OUTCOME for a todo. Benchmark todos report their
# outcome through the dedicated lane artifact; every other todo reports through its
# per-task evidence record.
outcome_file_for() {
  local todo="$1"
  case "$todo" in
    27) echo "$EVIDENCE_ROOT/task-27-benchmark.json" ;;
    28) echo "$EVIDENCE_ROOT/task-28-warm.json" ;;
    *)  echo "$EVIDENCE_ROOT/task-$todo-$PLAN.json" ;;
  esac
}

task_record_for() { echo "$EVIDENCE_ROOT/task-$1-$PLAN.json"; }

# BlockedReason token vocabulary (schemas/evidence-*.v1.json + warm-http-demo.v1.json
# enums, plus the binary-provenance tokens used by the privileged tests).
BLOCK_TOKENS='kvm_unavailable|docker_missing|firecracker_missing|firecracker_binary_missing|jailer_binary_missing|no_pinned_binary_verified|cgroup_unavailable|cgroup_delegate_failed|nested_unavailable|artifact_missing|page_cache_drop_unsupported'

TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_WORK"' EXIT
TASKS_JSONL="$TMPDIR_WORK/tasks.jsonl"
SCHEMA_JSONL="$TMPDIR_WORK/schema.jsonl"
ARITHMETIC_JSONL="$TMPDIR_WORK/arith.jsonl"
: > "$TASKS_JSONL"; : > "$SCHEMA_JSONL"; : > "$ARITHMETIC_JSONL"

# ---------------------------------------------------------------------------
# Outcome extractor (jq). Reads one evidence file on stdin; lane via --arg.
# Emits a single JSON object: {outcome, reason, violation, anti_mock, note, signals}.
# ---------------------------------------------------------------------------
read -r -d '' EXTRACTOR_JQ <<'JQ' || true
( .blocked_reason // null ) as $br
| ( if ($br|type)=="string" and ($br|length)>0 then $br else null end ) as $blocked_reason
| ( (.verdict // null) == "blocked" ) as $verdict_blocked
| ( ((.summary // {}).blocked // 0) > 0 and ((.summary // {}).pass // 0) == 0 ) as $summary_blocked
| ( (.host_preflight // {}).kvm_ok == false ) as $kvm_not_ok
| ( (.privileged_boot_evidence // {}).real_boot_outcome.outcome == "completed" ) as $real_boot
| ( [ ((.privileged_runs // [])[]) | select(.pass==true and .blocked==false) ] | length > 0 ) as $real_run_pass
| ( [ .. | strings | scan("(" + $tokens + ")") ] | flatten | unique ) as $found_tokens
| ( (.status // null) as $s | ($s=="fail" or $s=="failed" or $s=="error") ) as $status_fail
| ( (.verdict // null) as $v | ($v=="fail" or $v=="failed") ) as $verdict_fail
| ( (.test_results.exit_code // null) as $e | ($e != null and $e != 0) ) as $exit_fail
| ( ((.summary // {}).fail // 0) > 0 ) as $summary_fail
| ( $status_fail or $verdict_fail or $exit_fail or $summary_fail ) as $fail_signal
| ( (.status // null) as $s | ($s=="pass" or $s=="complete" or $s=="completed" or $s=="ok") ) as $status_pass
| ( (.verdict // null) as $v | ($v=="complete" or $v=="pass" or $v=="completed" or $v=="ok") ) as $verdict_pass
| ( (.test_results.exit_code // null) == 0 ) as $exit_pass
| ( ((.summary // {}).pass // 0) > 0 and ((.summary // {}).fail // 0) == 0 and ((.summary // {}).blocked // 0) == 0 ) as $summary_pass
| ( $status_pass or $verdict_pass or $exit_pass or $summary_pass ) as $pass_signal
| { blocked_reason:$blocked_reason, verdict_blocked:$verdict_blocked, summary_blocked:$summary_blocked,
    kvm_not_ok:$kvm_not_ok, real_boot:$real_boot, real_run_pass:$real_run_pass,
    found_tokens:$found_tokens, fail_signal:$fail_signal, pass_signal:$pass_signal } as $sig
| ( if $lane == "deterministic" then
      if ($sig.blocked_reason != null or $sig.verdict_blocked or $sig.summary_blocked) then
        {outcome:"fail", reason:("deterministic_lane_has_no_blocked_state" + (if $sig.blocked_reason != null then ":" + $sig.blocked_reason else "" end)), violation:"deterministic_blocked_not_allowed", note:"deterministic lane has no blocked state; counted as fail"}
      elif $sig.fail_signal then {outcome:"fail", reason:"deterministic_test_failure"}
      elif $sig.pass_signal then {outcome:"pass", reason:"deterministic_suite_green"}
      else {outcome:"fail", reason:"no_positive_signal", violation:"no_positive_signal"}
      end
    elif $lane == "privileged" then
      # Anti-mock is absolute (schema evidence-privileged.v1.json allOf rule): when
      # host_preflight.kvm_ok is false, NO privileged run may record pass — even a
      # claimed real boot, which would be contradictory evidence of a mock. This check
      # precedes real-substrate proof so a fabricated real_boot cannot evade it.
      if $sig.kvm_not_ok then {outcome:"blocked", reason:"kvm_not_ok", anti_mock:true, note:"anti-mock: privileged pass forbidden when host_preflight.kvm_ok is false"}
      elif ($sig.real_boot or $sig.real_run_pass) then
        ( if ($sig.blocked_reason != null or $sig.verdict_blocked) then {outcome:"blocked", reason:($sig.blocked_reason // "verdict_blocked"), note:"explicit blocked signal preserved over real-substrate proof"}
          else {outcome:"pass", reason:(if $sig.real_boot then "real_kvm_boot_completed" else "real_privileged_run_passed" end)}
          end )
      elif ($sig.blocked_reason != null) then {outcome:"blocked", reason:$sig.blocked_reason}
      elif $sig.verdict_blocked then {outcome:"blocked", reason:"verdict_blocked"}
      elif $sig.summary_blocked then {outcome:"blocked", reason:"privileged_runs_blocked"}
      elif ($sig.found_tokens | length > 0) then {outcome:"blocked", reason:($sig.found_tokens|join(",")), note:"blocked token present in privileged evidence; fail-closed"}
      elif $sig.fail_signal then {outcome:"fail", reason:"privileged_test_failure"}
      elif $sig.pass_signal then {outcome:"blocked", reason:"privileged_not_demonstrated_on_host", note:"status complete but no real-substrate proof; fail-closed, not promoted to pass"}
      else {outcome:"fail", reason:"no_positive_signal", violation:"no_positive_signal"}
      end
    elif $lane == "meta" then
      if ($sig.blocked_reason != null) then {outcome:"blocked", reason:$sig.blocked_reason}
      elif $sig.verdict_blocked then {outcome:"blocked", reason:"verdict_blocked"}
      elif $sig.summary_blocked then {outcome:"blocked", reason:"blocked"}
      elif $sig.fail_signal then {outcome:"fail", reason:"failure"}
      elif $sig.pass_signal then {outcome:"pass", reason:"task_complete"}
      else {outcome:"fail", reason:"no_positive_signal", violation:"no_positive_signal"}
      end
    else {outcome:"fail", reason:"unknown_lane", violation:"unknown_lane"}
    end ) as $d
| { outcome:$d.outcome, reason:$d.reason, violation:($d.violation // null),
    anti_mock:($d.anti_mock // false), note:($d.note // null),
    signals:{ blocked_reason:$sig.blocked_reason, verdict_blocked:$sig.verdict_blocked,
      summary_blocked:$sig.summary_blocked, kvm_not_ok:$sig.kvm_not_ok, real_boot:$sig.real_boot,
      real_run_pass:$sig.real_run_pass, blocked_tokens_found:$sig.found_tokens,
      fail_signal:$sig.fail_signal, pass_signal:$sig.pass_signal } }
JQ

# Benchmark-outcome extractor (jq). Reads the lane artifact on stdin.
read -r -d '' BENCH_EXTRACTOR_JQ <<'JQ'
( .class // null ) as $class
| ( has("pass") ) as $top_pass
| ( [ (.benchmarks // [])[] | has("pass") ] | any ) as $item_pass
| ( [ (.benchmarks // [])[] | select((.blocked_reason // null) != null) | .blocked_reason ] | unique ) as $bench_blocked_reasons
| ( [ (.benchmarks // [])[] | select( ((.cold // {}).samples // 0) == 0 and ((.warm // {}).samples // 0) == 0 ) ] | length ) as $zero_sample_items
| ( (.benchmarks // []) | length ) as $n_items
| ( (.blocked_reason // null) ) as $warm_blocked_reason
| ( if $class == "warm_http_demo" then
      ( if ($warm_blocked_reason != null) then {outcome:"blocked", reason:$warm_blocked_reason}
        else {outcome:"published", reason:"warm_demo_ran_distributions_recorded"} end )
    else
      ( if (($bench_blocked_reasons|length) > 0) then {outcome:"blocked", reason:($bench_blocked_reasons|join(","))}
        elif ($n_items > 0 and $zero_sample_items == $n_items) then {outcome:"blocked", reason:"all_benchmarks_zero_samples"}
        else {outcome:"published", reason:"benchmark_distributions_recorded"} end )
    end ) as $d
| { outcome:$d.outcome, reason:$d.reason,
    violation:(if ($top_pass or $item_pass) then "benchmark_has_pass_field" else null end),
    anti_mock:false,
    note:(if ($top_pass or $item_pass) then "anti-boolean: benchmark artifact carries a pass field" else null end),
    signals:{ class:$class, top_level_pass_field:$top_pass, item_pass_field:$item_pass,
      benchmark_blocked_reasons:$bench_blocked_reasons, warm_blocked_reason:$warm_blocked_reason,
      benchmark_items:$n_items, zero_sample_items:$zero_sample_items } }
JQ

# ---------------------------------------------------------------------------
# Per-todo processing
# ---------------------------------------------------------------------------
INTEGRITY_FAILURES=0
for todo in $(seq "$FIRST_TODO" "$LAST_TODO"); do
  lane="$(lane_for "$todo")"
  task_record="$(task_record_for "$todo")"
  outcome_file="$(outcome_file_for "$todo")"
  task_record_rel="${task_record#"$REPO_ROOT"/}"

  record_exists=false; record_valid=false
  [[ -f "$task_record" ]] && record_exists=true
  [[ "$record_exists" == true ]] && jq -e . "$task_record" >/dev/null 2>&1 && record_valid=true

  if [[ "$lane" == "benchmark" ]]; then src_file="$outcome_file"; else src_file="$task_record"; fi
  src_rel="${src_file#"$REPO_ROOT"/}"
  src_exists=false; src_valid=false
  [[ -f "$src_file" ]] && src_exists=true
  [[ "$src_exists" == true ]] && jq -e . "$src_file" >/dev/null 2>&1 && src_valid=true

  if [[ "$src_exists" != true ]]; then
    decision="$(jq -n '{outcome:"missing", reason:"evidence_artifact_missing", violation:"missing_artifact", anti_mock:false, note:("required evidence file not found: " + $r), signals:{}}' --arg r "$src_rel")"
  elif [[ "$src_valid" != true ]]; then
    decision="$(jq -n '{outcome:"invalid", reason:"evidence_not_valid_json", violation:"invalid_json", anti_mock:false, note:("evidence file is not valid JSON: " + $r), signals:{}}' --arg r "$src_rel")"
  elif [[ "$lane" == "benchmark" ]]; then
    decision="$(jq --arg lane "$lane" "$BENCH_EXTRACTOR_JQ" "$src_file")"
  else
    decision="$(jq --arg lane "$lane" --arg tokens "$BLOCK_TOKENS" "$EXTRACTOR_JQ" "$src_file")"
  fi

  outcome="$(jq -r '.outcome' <<<"$decision")"
  violation="$(jq -r '.violation // empty' <<<"$decision")"
  # Integrity failures are: invalid JSON, or a real semantic violation (benchmark
  # pass field, deterministic blocked, anti-mock breach, no positive signal).
  # A missing artifact is a COVERAGE failure handled by the --require-complete gate
  # below, so --allow-incomplete can report progress without a hard failure.
  if [[ "$outcome" == "invalid" ]]; then
    INTEGRITY_FAILURES=$((INTEGRITY_FAILURES+1))
  elif [[ -n "$violation" && "$violation" != "missing_artifact" ]]; then
    INTEGRITY_FAILURES=$((INTEGRITY_FAILURES+1))
  fi

  jq -n \
    --argjson todo "$todo" \
    --arg lane "$lane" \
    --arg task_record "$task_record_rel" \
    --argjson record_exists "$record_exists" \
    --argjson record_valid "$record_valid" \
    --arg outcome_source "$src_rel" \
    --argjson source_exists "$src_exists" \
    --argjson source_valid "$src_valid" \
    --argjson decision "$decision" '
    { todo:$todo, lane:$lane,
      task_record:$task_record,
      task_record_exists:$record_exists,
      task_record_valid_json:$record_valid,
      outcome_source:$outcome_source,
      outcome_source_exists:$source_exists,
      outcome_source_valid_json:$source_valid,
      outcome:$decision.outcome,
      reason:$decision.reason,
      violation:$decision.violation,
      anti_mock:$decision.anti_mock,
      note:$decision.note,
      signals:$decision.signals }' >> "$TASKS_JSONL"
done

# ---------------------------------------------------------------------------
# Lane-artifact schema validation (fail-closed invariants via jq).
# ---------------------------------------------------------------------------
validate_benchmark_artifact() {
  local file="$1" schema="$2"
  local rel="${file#"$REPO_ROOT"/}"
  local result
  if [[ ! -f "$file" ]]; then
    result="$(jq -n --arg f "$rel" --arg s "$schema" '{file:$f, schema:$s, valid:false, errors:["artifact_missing"]}')"
  else
    result="$(jq --arg schema "$schema" --arg rel "$rel" '
      def req_missing($req): ($req - (keys_unsorted));
      def extra_keys($allowed): (keys_unsorted - $allowed);
      . as $doc
      | ( if ($doc|type) != "object" then ["top_level_not_object"]
          else
            ( if $schema == "evidence-benchmark.v1.json" then
                ( req_missing(["class","host_metadata","benchmarks","workload","runtime_versions"]) | map("missing_top_level:" + .) )
                + ( extra_keys(["class","host_metadata","benchmarks","workload","runtime_versions"]) | map("unexpected_top_level:" + .) )
                + ( if $doc.class != "benchmark" then ["class_not_benchmark"] else [] end )
                + ( if ($doc|has("pass")) then ["anti_boolean_violation:top_level_pass"] else [] end )
                + ( ((($doc.host_metadata // {})|req_missing(["cpu","kernel","kvm_api_version","page_cache_state","memory_size_mib","vcpu_count","cgroup_v2","nested"])) | map("host_metadata_missing:" + .)) )
                + ( ((($doc.workload // {})|req_missing(["name","payload_sha256"])) | map("workload_missing:" + .)) )
                + ( if (($doc.workload.payload_sha256 // "")|test("^[0-9a-f]{64}$")|not) then ["workload_payload_sha256_not_64hex"] else [] end )
                + ( ((($doc.runtime_versions // {})|extra_keys(["firecracker","docker"])) | map("runtime_versions_unexpected:" + .)) )
                + ( [ ($doc.benchmarks // [])[] |
                      ( req_missing(["name","target_ms","unit","p50","p95","p99","cold","warm","blocked_reason"]) | map("benchmark_item_missing:" + .) )
                      + ( if has("pass") then ["anti_boolean_violation:benchmark_item_pass"] else [] end )
                      + ( if ((.unit // "")|IN("ms","us","s","rps","B/s","KiB/s","MiB/s")|not) then ["benchmark_item_bad_unit:" + (.unit|tostring)] else [] end )
                      + ( ((.cold // {})|req_missing(["samples","p50","p95","p99","min_ms","max_ms"]) | map("cold_missing:" + .)) )
                      + ( ((.warm // {})|req_missing(["samples","p50","p95","p99","min_ms","max_ms"]) | map("warm_missing:" + .)) )
                    ] | flatten )
              else
                ( req_missing(["class","host_metadata","workload","cold_first_call_ms","warm_p50_ms","warm_p95_ms","warm_p99_ms","warm","warmup_count","request_trials","restore_trials","restore_failures","cold_phases","cleanup","blocked_reason","blocked_detail"]) | map("missing_top_level:" + .) )
                + ( extra_keys(["class","host_metadata","workload","cold_first_call_ms","warm_p50_ms","warm_p95_ms","warm_p99_ms","warm","warmup_count","request_trials","restore_trials","restore_failures","cold_phases","cleanup","blocked_reason","blocked_detail"]) | map("unexpected_top_level:" + .) )
                + ( if $doc.class != "warm_http_demo" then ["class_not_warm_http_demo"] else [] end )
                + ( if ($doc|has("pass")) then ["anti_boolean_violation:top_level_pass"] else [] end )
                + ( ((($doc.host_metadata // {})|req_missing(["cpu","kernel","kvm_api_version","page_cache_state","memory_size_mib","vcpu_count","cgroup_v2","nested"])) | map("host_metadata_missing:" + .)) )
                + ( ((($doc.workload // {})|req_missing(["name","payload_sha256"])) | map("workload_missing:" + .)) )
                + ( if (($doc.workload.payload_sha256 // "")|test("^[0-9a-f]{64}$")|not) then ["workload_payload_sha256_not_64hex"] else [] end )
                + ( ((($doc.warm // {})|req_missing(["samples","failures","p50","p95","p99","min_ms","max_ms"])) | map("warm_missing:" + .)) )
                + ( if ($doc.cold_phases != null) then ((($doc.cold_phases)|req_missing(["socket_ready_ms","configured_ms","guest_ready_ms","snapshot_ready_ms","restore_ready_ms","request_ms"])) | map("cold_phases_missing:" + .)) else [] end )
                + ( ((($doc.cleanup // {})|req_missing(["released_vms","snapshot_discarded"])) | map("cleanup_missing:" + .)) )
                + ( if (($doc.blocked_reason != null) and ($doc.blocked_reason|IN("kvm_unavailable","docker_missing","firecracker_missing","page_cache_drop_unsupported","cgroup_unavailable","nested_unavailable","artifact_missing")|not)) then ["blocked_reason_not_in_enum:" + ($doc.blocked_reason|tostring)] else [] end )
              end )
          end ) as $errors
      | {file:$rel, schema:$schema, valid:(($errors|length)==0), errors:$errors}
    ' "$file")"
  fi
  printf '%s\n' "$result" >> "$SCHEMA_JSONL"
  if [[ "$(jq -r '.valid' <<<"$result")" != "true" ]]; then
    INTEGRITY_FAILURES=$((INTEGRITY_FAILURES+1))
  fi
}

# Summary-arithmetic reconciliation (schemas/README.md assigns this to the validator).
for f in "$EVIDENCE_ROOT"/*.json; do
  [[ -e "$f" ]] || continue
  rel="${f#"$REPO_ROOT"/}"
  jq -c --arg rel "$rel" '
    [ .. | objects | select(has("summary")) | .summary | objects
      | select(has("total") and has("pass") and has("fail"))
      | . as $s | ($s.total) as $t
      | (($s.pass // 0) + ($s.fail // 0) + ($s.blocked // 0)) as $sum
      | select($t != $sum)
      | {total:$t, computed_sum:$sum, pass:($s.pass//0), fail:($s.fail//0), blocked:($s.blocked//0)}
    ] as $bad
    | select(($bad|length) > 0)
    | {file:$rel, arithmetic_mismatches:$bad}
  ' "$f" 2>/dev/null >> "$ARITHMETIC_JSONL" || true
done
[[ -s "$ARITHMETIC_JSONL" ]] && INTEGRITY_FAILURES=$((INTEGRITY_FAILURES+1))

validate_benchmark_artifact "$EVIDENCE_ROOT/task-27-benchmark.json" "evidence-benchmark.v1.json"
validate_benchmark_artifact "$EVIDENCE_ROOT/task-28-warm.json" "warm-http-demo.v1.json"

# ---------------------------------------------------------------------------
# Assemble summary.json
# ---------------------------------------------------------------------------
GENERATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
GIT_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"

jq -n \
  --arg plan "$PLAN" \
  --arg generated_at "$GENERATED_AT" \
  --arg git_head "$GIT_HEAD" \
  --argjson first "$FIRST_TODO" \
  --argjson last "$LAST_TODO" \
  --argjson require_complete "$REQUIRE_COMPLETE" \
  --slurpfile tasks "$TASKS_JSONL" \
  --slurpfile schema "$SCHEMA_JSONL" \
  --slurpfile arith "$ARITHMETIC_JSONL" '
  def lc($lane; $outcome): ([ $tasks[] | select(.lane==$lane and .outcome==$outcome) ] | length);
  def lt($lane; $outcome): ([ $tasks[] | select(.lane==$lane and .outcome==$outcome) | .todo ] | sort);
  ($tasks | map(.todo)) as $present
  | ([ range($first; $last+1) ]) as $all
  | ([ $tasks[] | select(.outcome=="missing" or .outcome=="invalid") | .todo ] | sort) as $missing
  | ([ $tasks[] | select(.violation != null) ]) as $violations
  | {
      schema_version: 1,
      plan: $plan,
      generated_at: $generated_at,
      git_head: $git_head,
      generator: "scripts/aggregate-evidence.sh",
      strict_mode: ($require_complete == 1),
      outcome_vocabulary: {
        deterministic: ["pass","fail"],
        privileged: ["pass","blocked","fail"],
        benchmark: ["published","blocked","fail"],
        meta: ["pass","blocked","fail"]
      },
      fail_closed_rules: [
        "blocked evidence is never erased: an explicit blocked signal always yields blocked",
        "privileged pass requires affirmative real-substrate proof (real boot / real run); otherwise blocked, never promoted to pass",
        "benchmark never records pass: distributions are published or blocked (anti-boolean)",
        "deterministic lane has no blocked state: a blocked deterministic todo is a violation counted as fail",
        "a missing evidence artifact is a failure"
      ],
      todo_range: {first:$first, last:$last, expected:($last - $first + 1)},
      coverage: {
        expected_todos: ($last - $first + 1),
        evidence_present: ([ $tasks[] | select(.outcome != "missing" and .outcome != "invalid") ] | length),
        evidence_missing: ($missing | length),
        missing_todos: $missing,
        complete: (($missing | length) == 0)
      },
      lanes: {
        deterministic: {
          todos: ([ $tasks[] | select(.lane=="deterministic") | .todo ] | sort),
          pass: lc("deterministic";"pass"), blocked: lc("deterministic";"blocked"),
          fail: lc("deterministic";"fail"), missing: lc("deterministic";"missing"),
          pass_todos: lt("deterministic";"pass"), fail_todos: lt("deterministic";"fail")
        },
        privileged: {
          todos: ([ $tasks[] | select(.lane=="privileged") | .todo ] | sort),
          pass: lc("privileged";"pass"), blocked: lc("privileged";"blocked"),
          fail: lc("privileged";"fail"), missing: lc("privileged";"missing"),
          pass_todos: lt("privileged";"pass"), blocked_todos: lt("privileged";"blocked"),
          blocked_reasons: ([ $tasks[] | select(.lane=="privileged" and .outcome=="blocked") | {todo, reason} ])
        },
        benchmark: {
          todos: ([ $tasks[] | select(.lane=="benchmark") | .todo ] | sort),
          published: lc("benchmark";"published"), blocked: lc("benchmark";"blocked"),
          fail: lc("benchmark";"fail"), missing: lc("benchmark";"missing"),
          pass: 0, pass_forbidden: true,
          published_todos: lt("benchmark";"published"), blocked_todos: lt("benchmark";"blocked")
        },
        meta: {
          todos: ([ $tasks[] | select(.lane=="meta") | .todo ] | sort),
          pass: lc("meta";"pass"), blocked: lc("meta";"blocked"),
          fail: lc("meta";"fail"), missing: lc("meta";"missing"),
          pass_todos: lt("meta";"pass"), blocked_todos: lt("meta";"blocked"), missing_todos: lt("meta";"missing")
        }
      },
      totals: {
        pass: ([ $tasks[] | select(.outcome=="pass") ] | length),
        blocked: ([ $tasks[] | select(.outcome=="blocked") ] | length),
        published: ([ $tasks[] | select(.outcome=="published") ] | length),
        fail: ([ $tasks[] | select(.outcome=="fail") ] | length),
        missing: ([ $tasks[] | select(.outcome=="missing") ] | length),
        invalid: ([ $tasks[] | select(.outcome=="invalid") ] | length)
      },
      schema_validation: {
        artifacts: $schema,
        all_valid: ([ $schema[] | .valid ] | all),
        arithmetic_mismatches: $arith,
        arithmetic_reconciled: (($arith | length) == 0)
      },
      semantic_violations: ([ $violations[] | select(.violation != "missing_artifact") ] | map({todo, lane, outcome, violation, reason, note})),
      semantic_violation_count: ([ $violations[] | select(.violation != "missing_artifact") ] | length),
      integrity_failures: ([ $violations[] | select(.violation == "invalid_json" or .violation == "benchmark_has_pass_field" or .violation == "deterministic_blocked_not_allowed") ] | map({todo, lane, violation, reason})),
      tasks: ($tasks | sort_by(.todo))
    }
' > "$OUT"

# ---------------------------------------------------------------------------
# Human-readable report + exit code
# ---------------------------------------------------------------------------
echo "==================================================================="
echo " kvm-microvm-orchestrator — verification matrix (evidence reducer)"
echo "==================================================================="
jq -r '
  "generated_at: \(.generated_at)   git_head: \(.git_head[0:12])   strict: \(.strict_mode)",
  "coverage: \(.coverage.evidence_present)/\(.coverage.expected_todos) todos have evidence; missing: \(.coverage.missing_todos|map(tostring)|join(","))",
  "",
  "lane           pass  blocked  published  fail  missing",
  "deterministic  \(.lanes.deterministic.pass)      \(.lanes.deterministic.blocked)        -          \(.lanes.deterministic.fail)     \(.lanes.deterministic.missing)",
  "privileged     \(.lanes.privileged.pass)        \(.lanes.privileged.blocked)        -          \(.lanes.privileged.fail)     \(.lanes.privileged.missing)",
  "benchmark      -        \(.lanes.benchmark.blocked)        \(.lanes.benchmark.published)          \(.lanes.benchmark.fail)     \(.lanes.benchmark.missing)",
  "meta           \(.lanes.meta.pass)        \(.lanes.meta.blocked)        -          \(.lanes.meta.fail)     \(.lanes.meta.missing)",
  "",
  "totals: pass=\(.totals.pass) blocked=\(.totals.blocked) published=\(.totals.published) fail=\(.totals.fail) missing=\(.totals.missing) invalid=\(.totals.invalid)",
  "privileged pass todos:     \(.lanes.privileged.pass_todos|map(tostring)|join(","))",
  "benchmark published todos: \(.lanes.benchmark.published_todos|map(tostring)|join(","))   blocked: \(.lanes.benchmark.blocked_todos|map(tostring)|join(","))",
  "schema validation: all_valid=\(.schema_validation.all_valid)  arithmetic_reconciled=\(.schema_validation.arithmetic_reconciled)",
  "semantic_violations: \(.semantic_violation_count)"
' "$OUT"
echo ""
echo "summary written to: ${OUT#"$REPO_ROOT"/}"

EXIT=0
if [[ $INTEGRITY_FAILURES -gt 0 ]]; then
  echo "INTEGRITY FAILURE: $INTEGRITY_FAILURES integrity problem(s) (invalid JSON, schema/anti-boolean/anti-mock violation, arithmetic mismatch, or missing artifact)." >&2
  EXIT=1
fi
if [[ $REQUIRE_COMPLETE -eq 1 ]]; then
  mc="$(jq -r '.coverage.evidence_missing' "$OUT")"
  if [[ "$mc" != "0" ]]; then
    echo "STRICT: $mc todo(s) lack evidence (missing artifact is a failure). Use --allow-incomplete for a progress view." >&2
    EXIT=1
  fi
fi
exit "$EXIT"
