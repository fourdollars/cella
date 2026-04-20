#!/usr/bin/env bash
set -euo pipefail

# Token Broker E2E smoke cycle:
# dummy-token -> broker PAT replacement -> audit evidence

CONTAINER="${1:-juju-ec4ec2-0}"
PORT="${PORT:-9081}"
PAT_ENV_KEY="${PAT_ENV_KEY:-CELLA_BROKER_TEST_PAT}"
TOKEN_ID="${TOKEN_ID:-tok-cron-e2e}"
POOL="${POOL:-pool_cron}"
START_TIMEOUT_SEC="${START_TIMEOUT_SEC:-30}"
LOG_DIR="${LOG_DIR:-/tmp/cella}"
PROXY_BIN="${PROXY_BIN:-$LOG_DIR/cella-proxy-e2e-bin}"
PREEMPT_PORT="${PREEMPT_PORT:-1}"
SUMMARY_SCHEMA_VERSION="token_broker_e2e_summary.v1"
SUMMARY_COMPAT_MIN_SCHEMA="token_broker_e2e_summary.v1"
SELFTEST_SCHEMA_VERSION="token_broker_selftest.v1"
SELFTEST_COMPAT_MIN_SCHEMA="token_broker_selftest.v1"
VALIDATOR_VERSION="token_broker_validator.v1"
VALIDATOR_COMPAT_MIN_VERSION="token_broker_validator.v1"

mkdir -p "$LOG_DIR"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
LOG_FILE="$LOG_DIR/token-broker-e2e-$STAMP.log"
BODY_FILE="$LOG_DIR/token-broker-e2e-body-$STAMP.json"
REMOTE_BODY_FILE="/tmp/cella-broker-e2e-$STAMP.json"
SUMMARY_FILE="$LOG_DIR/token-broker-e2e-summary-$STAMP.json"
CURL_TIMEOUT_SEC="${CURL_TIMEOUT_SEC:-20}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proxy_pid=""
proxy_stopped=0
pat_injected_dummy=0
pat_detected_dummy=0
pat_shape_invalid=0
pat_shape_kind="unknown"
http_audit_mismatch=0
precheck_skipped_reason=""
precheck_failure_class=""
cycle_outcome=""
goal_state=""
goal_state_reached=0
next_action=""
next_action_cmd=""
next_action_steps=0
next_action_auto_runnable=0
next_action_auto_run_blocker=""
next_action_template_vars=""
next_action_template_var_count=0
next_action_missing_inputs=""
next_action_missing_input_count=0
next_action_missing_input_env_keys=""
next_action_missing_input_env_key_count=0
next_action_missing_input_export_cmds=""
next_action_missing_input_export_cmd_count=0
next_action_env_ref_cmds=""
next_action_env_ref_cmd_count=0
next_action_ready_cmds=""
next_action_ready_cmd_count=0
next_action_ready_cmd_hash=""
next_action_ready_cmd_auto_runnable=0
next_action_ready_cmd_blocker=""
next_action_ready_prereq_cmds=""
next_action_ready_prereq_cmd_count=0
next_action_ready_prereq_cmd_hash=""
next_action_execute_cmds=""
next_action_execute_cmd_count=0
next_action_execute_cmd_hash=""
next_action_execute_cmd_blocker=""
next_action_execute_cmd_auto_runnable=0
next_action_execute_env_ref_cmds=""
next_action_execute_env_ref_cmd_count=0
next_action_execute_env_ref_cmd_hash=""
next_action_execute_env_ref_cmd_blocker=""
next_action_execute_env_ref_cmd_auto_runnable=0
next_action_best_auto_cmds=""
next_action_best_auto_cmd_count=0
next_action_best_auto_cmd_hash=""
next_action_best_auto_cmd_source=""
next_action_best_auto_cmd_blocker=""
next_action_best_auto_cmd_auto_runnable=0
next_action_best_auto_cmd_dispatch_mode=""
next_action_missing_secret_env_keys=""
next_action_missing_secret_env_key_count=0
next_action_requires_manual_input=0
next_action_dispatch_mode=""
next_action_cmd_hash=""
remote_body_cleanup_status="not_attempted"

classify_e2e_result() {
  local audit="$1"
  local broker_src="$2"
  local session_state="$3"
  local last_test="$4"

  if [[ -z "$broker_src" || "$broker_src" == "-" ]]; then
    echo "broker_not_applied"
    return
  fi

  if [[ "$audit" == "401" ]] && [[ "$session_state" == exchange-fail:direct:* ]] && [[ "$session_state" == *"|pat:"* ]]; then
    echo "upstream_reject_after_broker_replace"
    return
  fi

  if [[ "$audit" == "200" ]] && [[ "$last_test" == "ok" ]]; then
    echo "exchange_success"
    return
  fi

  if [[ "$audit" == "429" ]]; then
    echo "broker_or_rph_block"
    return
  fi

  if [[ "$session_state" == "in-use" || "$session_state" == session:* ]]; then
    echo "broker_path_active"
    return
  fi

  echo "needs_manual_review"
}

action_hint_for_classification() {
  local cls="$1"
  case "$cls" in
    upstream_reject_after_broker_replace)
      echo "rotate_or_fix_pat"
      ;;
    exchange_success)
      echo "keep_current_config"
      ;;
    broker_or_rph_block)
      echo "check_broker_health_and_rph_policy"
      ;;
    broker_path_active)
      echo "run_inference_smoke_next"
      ;;
    broker_not_applied)
      echo "check_redirect_and_group_mapping"
      ;;
    needs_manual_review)
      echo "inspect_log_and_summary"
      ;;
    *)
      echo "inspect_log_and_summary"
      ;;
  esac
}

precheck_cmd_for_action_hint() {
  local hint="$1"
  case "$hint" in
    rotate_or_fix_pat)
      cat <<EOF
${repo_root}/scripts/token_broker_e2e_cycle.sh __pat_check_env__ ${PAT_ENV_KEY}
EOF
      ;;
    keep_current_config)
      echo "true"
      ;;
    check_broker_health_and_rph_policy)
      cat <<EOF
grep -E 'broker|audit' ${LOG_FILE} >/dev/null
grep -E 'broker|audit' ${LOG_FILE} | tail -n 20
EOF
      ;;
    run_inference_smoke_next)
      cat <<EOF
test -f ${LOG_FILE}
grep -q '/copilot_internal/v2/token' ${LOG_FILE}
EOF
      ;;
    check_redirect_and_group_mapping)
      cat <<EOF
sudo -n nft --handle list chain ip cella_tproxy prerouting
sudo -n ss -ltnp | grep :${PORT} || true
EOF
      ;;
    inspect_log_and_summary)
      cat <<EOF
test -f ${SUMMARY_FILE}
test -f ${LOG_FILE}
EOF
      ;;
    *)
      echo "true"
      ;;
  esac
}

run_cmd_for_action_hint() {
  local hint="$1"
  case "$hint" in
    rotate_or_fix_pat)
      cat <<EOF
${PAT_ENV_KEY}=<valid_pat> ./scripts/token_broker_e2e_cycle.sh ${CONTAINER}
cat ${SUMMARY_FILE}
EOF
      ;;
    keep_current_config)
      cat <<EOF
./scripts/token_broker_e2e_cycle.sh ${CONTAINER}
cat ${SUMMARY_FILE}
EOF
      ;;
    check_broker_health_and_rph_policy)
      cat <<EOF
grep -E 'broker|audit' ${LOG_FILE} | tail -n 80
cat ${SUMMARY_FILE}
EOF
      ;;
    run_inference_smoke_next)
      cat <<EOF
./scripts/token_broker_e2e_cycle.sh ${CONTAINER}
cat ${SUMMARY_FILE}
EOF
      ;;
    check_redirect_and_group_mapping)
      cat <<EOF
./scripts/token_broker_e2e_cycle.sh ${CONTAINER}
sudo -n nft --handle list chain ip cella_tproxy prerouting
EOF
      ;;
    inspect_log_and_summary)
      cat <<EOF
cat ${SUMMARY_FILE}
tail -n 80 ${LOG_FILE}
EOF
      ;;
    *)
      echo "cat ${SUMMARY_FILE}"
      ;;
  esac
}

stop_conditions_for_action_hint() {
  local hint="$1"
  case "$hint" in
    rotate_or_fix_pat)
      cat <<EOF
precheck_all_must_pass
require_non_dummy_pat
require_valid_pat_shape
EOF
      ;;
    *)
      echo "precheck_all_must_pass"
      ;;
  esac
}

extract_kind_from_output() {
  local out="$1"
  local line token

  line="$(printf '%s\n' "$out" | grep -E 'PAT_CHECK_(FAIL|OK)' | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    line="$(printf '%s\n' "$out" | tail -n 1)"
  fi

  token="$(printf '%s\n' "$line" | grep -oE 'kind=[^[:space:]]+' | head -n 1 || true)"
  if [[ -n "$token" ]]; then
    echo "${token#kind=}"
  fi
}

run_precheck_commands() {
  local cmds="$1"
  precheck_failed=0
  precheck_failed_cmds=""
  precheck_failed_outputs=""
  precheck_failed_rcs=""
  precheck_failed_kinds=""

  while IFS= read -r cmd; do
    local out rc last_line kind_token
    cmd="$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' <<<"$cmd")"
    [[ -z "$cmd" ]] && continue

    set +e
    out="$(bash -lc "$cmd" 2>&1)"
    rc=$?
    set -e

    if [[ "$rc" -ne 0 ]]; then
      precheck_failed=1
      precheck_failed_cmds+="$cmd"$'\n'
      precheck_failed_rcs+="$cmd => rc=$rc"$'\n'
      last_line="$(printf '%s\n' "$out" | tail -n 1)"
      if [[ -z "$last_line" ]]; then
        last_line="(no output)"
      fi
      precheck_failed_outputs+="$cmd => $last_line"$'\n'
      kind_token="$(extract_kind_from_output "$out")"
      if [[ -n "$kind_token" ]]; then
        precheck_failed_kinds+="$cmd => ${kind_token}"$'\n'
      fi
    fi
  done <<<"$cmds"
}

classify_precheck_failure() {
  local skipped_reason="$1"
  local failed_flag="$2"
  local failed_kinds="$3"
  local failed_rcs="$4"

  if [[ -n "$skipped_reason" ]]; then
    echo "skipped:${skipped_reason}"
    return
  fi
  if [[ "$failed_flag" != "1" ]]; then
    echo "none"
    return
  fi
  if [[ "$failed_kinds" == *"dummy_placeholder"* ]]; then
    echo "pat_dummy_placeholder"
    return
  fi
  if [[ "$failed_kinds" == *"classic_prefix_too_short"* || "$failed_kinds" == *"fine_grained_prefix_too_short"* || "$failed_kinds" == *"unknown_prefix"* || "$failed_kinds" == *"empty"* ]]; then
    echo "pat_shape_invalid"
    return
  fi
  if [[ "$failed_rcs" == *"rc=127"* ]]; then
    echo "precheck_cmd_not_found"
    return
  fi
  echo "precheck_other"
}

classify_cycle_outcome() {
  local blocker="$1"
  local e2e_class="$2"

  if [[ -n "$blocker" ]]; then
    echo "blocked:${blocker}"
    return
  fi

  case "$e2e_class" in
    exchange_success)
      echo "success"
      ;;
    broker_path_active)
      echo "broker_path_active"
      ;;
    upstream_reject_after_broker_replace)
      echo "upstream_reject_after_replace"
      ;;
    broker_not_applied)
      echo "broker_not_applied"
      ;;
    broker_or_rph_block)
      echo "rph_or_broker_block"
      ;;
    needs_manual_review)
      echo "manual_review"
      ;;
    *)
      echo "unknown"
      ;;
  esac
}

classify_goal_state() {
  local cycle="$1"

  case "$cycle" in
    success)
      echo "success"
      ;;
    broker_path_active)
      echo "broker_path_active"
      ;;
    *)
      echo "not_reached"
      ;;
  esac
}

goal_state_reached_of() {
  local goal="$1"
  if [[ "$goal" == "not_reached" || -z "$goal" ]]; then
    echo "0"
  else
    echo "1"
  fi
}

classify_next_action() {
  local cycle="$1"
  local precheck_class="$2"
  local hint="$3"

  case "$cycle" in
    blocked:dummy_pat_injected|blocked:dummy_pat_detected)
      echo "provide_real_pat"
      return
      ;;
    blocked:pat_shape_invalid)
      echo "provide_valid_pat_shape"
      return
      ;;
    blocked:precheck_failed)
      case "$precheck_class" in
        pat_dummy_placeholder)
          echo "provide_real_pat"
          return
          ;;
        pat_shape_invalid)
          echo "provide_valid_pat_shape"
          return
          ;;
        precheck_cmd_not_found)
          echo "fix_precheck_command_path"
          return
          ;;
      esac
      echo "inspect_precheck_failure"
      return
      ;;
  esac

  case "$cycle" in
    upstream_reject_after_replace)
      echo "rotate_or_fix_pat"
      ;;
    broker_path_active|success)
      echo "run_inference_smoke"
      ;;
    rph_or_broker_block)
      echo "check_broker_health_and_rph_policy"
      ;;
    broker_not_applied)
      echo "check_redirect_and_group_mapping"
      ;;
    manual_review|unknown)
      echo "inspect_log_and_summary"
      ;;
    *)
      if [[ -n "$hint" ]]; then
        echo "$hint"
      else
        echo "inspect_log_and_summary"
      fi
      ;;
  esac
}

next_action_cmd_for_next_action() {
  local next="$1"

  case "$next" in
    provide_real_pat|provide_valid_pat_shape)
      cat <<EOF
${PAT_ENV_KEY}=<valid_pat> ${repo_root}/scripts/token_broker_e2e_cycle.sh __pat_check_env__ ${PAT_ENV_KEY}
${PAT_ENV_KEY}=<valid_pat> ./scripts/token_broker_e2e_cycle.sh ${CONTAINER}
EOF
      ;;
    rotate_or_fix_pat)
      cat <<EOF
${PAT_ENV_KEY}=<valid_pat> ./scripts/token_broker_e2e_cycle.sh ${CONTAINER}
EOF
      ;;
    run_inference_smoke)
      cat <<EOF
./scripts/token_broker_e2e_cycle.sh ${CONTAINER}
EOF
      ;;
    fix_precheck_command_path)
      cat <<EOF
test -x ${repo_root}/scripts/token_broker_e2e_cycle.sh
EOF
      ;;
    check_broker_health_and_rph_policy)
      cat <<EOF
grep -E 'broker|audit' ${LOG_FILE} | tail -n 80
EOF
      ;;
    check_redirect_and_group_mapping)
      cat <<EOF
sudo -n nft --handle list chain ip cella_tproxy prerouting
sudo -n ss -ltnp | grep :${PORT} || true
EOF
      ;;
    inspect_precheck_failure|inspect_log_and_summary)
      cat <<EOF
cat ${SUMMARY_FILE}
tail -n 120 ${LOG_FILE}
EOF
      ;;
    *)
      echo "cat ${SUMMARY_FILE}"
      ;;
  esac
}

should_skip_precheck() {
  local hint="$1"
  local injected="$2"

  if [[ "$hint" == "rotate_or_fix_pat" && "$injected" == "1" ]]; then
    return 0
  fi

  return 1
}

effective_precheck_steps() {
  local total_steps="$1"
  local skipped_reason="$2"

  if [[ -n "$skipped_reason" ]]; then
    echo "0"
    return
  fi

  echo "$total_steps"
}

count_nonempty_lines() {
  local text="$1"
  printf '%s\n' "$text" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' '
}

next_action_cmd_is_templated() {
  local cmd_text="$1"
  [[ "$cmd_text" == *"<valid_pat>"* ]]
}

next_action_cmd_blocker() {
  local cmd_text="$1"
  local steps

  steps="$(count_nonempty_lines "$cmd_text")"
  if [[ "$steps" -eq 0 ]]; then
    echo "no_steps"
    return
  fi
  if next_action_cmd_is_templated "$cmd_text"; then
    echo "templated_pat"
    return
  fi
  echo "none"
}

next_action_cmd_auto_runnable() {
  local cmd_text="$1"
  local blocker

  blocker="$(next_action_cmd_blocker "$cmd_text")"
  if [[ "$blocker" == "none" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

next_action_cmd_hash_of() {
  local cmd_text="$1"
  local steps

  steps="$(count_nonempty_lines "$cmd_text")"
  if [[ "$steps" -eq 0 ]]; then
    echo ""
    return
  fi

  CMD_TEXT="$cmd_text" python3 - <<'PY'
import hashlib
import os

text = os.environ.get("CMD_TEXT", "")
print(hashlib.sha256(text.encode("utf-8")).hexdigest()[:12])
PY
}

next_action_template_vars_of() {
  local cmd_text="$1"
  CMD_TEXT="$cmd_text" python3 - <<'PY'
import os
import re

text = os.environ.get("CMD_TEXT", "")
seen = []
for m in re.findall(r"<[^>]+>", text):
    if m not in seen:
        seen.append(m)
print("\n".join(seen))
PY
}

next_action_template_var_count_of() {
  local vars_text="$1"
  count_nonempty_lines "$vars_text"
}

next_action_missing_inputs_of() {
  local vars_text="$1"
  VARS_TEXT="$vars_text" python3 - <<'PY'
import os

text = os.environ.get("VARS_TEXT", "")
out = []
for raw in text.splitlines():
    s = raw.strip()
    if not s:
        continue
    if s.startswith("<") and s.endswith(">") and len(s) >= 3:
        s = s[1:-1].strip()
    if s and s not in out:
        out.append(s)
print("\n".join(out))
PY
}

next_action_missing_input_count_of() {
  local missing_inputs_text="$1"
  count_nonempty_lines "$missing_inputs_text"
}

next_action_missing_input_env_keys_of() {
  local missing_inputs_text="$1"
  MISSING_INPUTS_TEXT="$missing_inputs_text" python3 - <<'PY'
import os

mapping = {
    "valid_pat": "CELLA_BROKER_TEST_PAT",
    "target_container": "CELLA_BROKER_TEST_CONTAINER",
    "container": "CELLA_BROKER_TEST_CONTAINER",
}

text = os.environ.get("MISSING_INPUTS_TEXT", "")
out = []
for raw in text.splitlines():
    key = mapping.get(raw.strip())
    if key and key not in out:
        out.append(key)
print("\n".join(out))
PY
}

next_action_missing_input_env_key_count_of() {
  local missing_input_env_keys_text="$1"
  count_nonempty_lines "$missing_input_env_keys_text"
}

next_action_missing_secret_env_keys_of() {
  local missing_input_env_keys_text="$1"
  MISSING_INPUT_ENV_KEYS_TEXT="$missing_input_env_keys_text" python3 - <<'PY'
import os

text = os.environ.get("MISSING_INPUT_ENV_KEYS_TEXT", "")
out = []
for raw in text.splitlines():
    key = raw.strip()
    if not key:
        continue
    key_u = key.upper()
    if any(marker in key_u for marker in ("PAT", "TOKEN", "SECRET", "PASSWORD", "KEY")):
        if key not in out:
            out.append(key)
print("\n".join(out))
PY
}

next_action_missing_secret_env_key_count_of() {
  local missing_secret_env_keys_text="$1"
  count_nonempty_lines "$missing_secret_env_keys_text"
}

next_action_missing_input_export_cmds_of() {
  local missing_input_env_keys_text="$1"
  MISSING_INPUT_ENV_KEYS_TEXT="$missing_input_env_keys_text" python3 - <<'PY'
import os

placeholder = {
    "CELLA_BROKER_TEST_PAT": "<valid_pat>",
    "CELLA_BROKER_TEST_CONTAINER": "<container_name>",
}

text = os.environ.get("MISSING_INPUT_ENV_KEYS_TEXT", "")
out = []
for raw in text.splitlines():
    key = raw.strip()
    if not key:
        continue
    value = placeholder.get(key, "<value>")
    cmd = f"export {key}='{value}'"
    if cmd not in out:
        out.append(cmd)
print("\n".join(out))
PY
}

next_action_missing_input_export_cmd_count_of() {
  local missing_input_export_cmds_text="$1"
  count_nonempty_lines "$missing_input_export_cmds_text"
}

next_action_env_ref_cmds_of() {
  local cmd_text="$1"
  CMD_TEXT="$cmd_text" python3 - <<'PY'
import os

text = os.environ.get("CMD_TEXT", "")
mapping = {
    "<valid_pat>": "${CELLA_BROKER_TEST_PAT}",
    "<target_container>": "${CELLA_BROKER_TEST_CONTAINER}",
    "<container_name>": "${CELLA_BROKER_TEST_CONTAINER}",
    "<container>": "${CELLA_BROKER_TEST_CONTAINER}",
}
for src, dst in mapping.items():
    text = text.replace(src, dst)
print(text)
PY
}

next_action_env_ref_cmd_count_of() {
  local env_ref_cmds_text="$1"
  count_nonempty_lines "$env_ref_cmds_text"
}

next_action_ready_cmds_of() {
  local export_cmds_text="$1"
  local env_ref_cmds_text="$2"
  EXPORT_CMDS_TEXT="$export_cmds_text" ENV_REF_CMDS_TEXT="$env_ref_cmds_text" python3 - <<'PY'
import os

exp = os.environ.get("EXPORT_CMDS_TEXT", "")
ref = os.environ.get("ENV_REF_CMDS_TEXT", "")
out = []
for block in (exp, ref):
    for raw in block.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s not in out:
            out.append(s)
print("\n".join(out))
PY
}

next_action_ready_cmd_count_of() {
  local ready_cmds_text="$1"
  count_nonempty_lines "$ready_cmds_text"
}

next_action_ready_cmd_blocker_of() {
  local ready_cmds_text="$1"
  next_action_cmd_blocker "$ready_cmds_text"
}

next_action_ready_cmd_auto_runnable_of() {
  local ready_cmds_text="$1"
  local blocker

  blocker="$(next_action_ready_cmd_blocker_of "$ready_cmds_text")"
  if [[ "$blocker" == "none" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

next_action_ready_prereq_cmds_of() {
  local missing_secret_env_keys_text="$1"
  local pat_env_key="$2"
  local repo_root_path="$3"

  MISSING_SECRET_ENV_KEYS_TEXT="$missing_secret_env_keys_text" \
  PAT_ENV_KEY_INPUT="$pat_env_key" \
  REPO_ROOT_PATH="$repo_root_path" \
  python3 - <<'PY'
import os

keys = [line.strip() for line in os.environ.get("MISSING_SECRET_ENV_KEYS_TEXT", "").splitlines() if line.strip()]
pat_env_key = os.environ.get("PAT_ENV_KEY_INPUT", "")
repo_root = os.environ.get("REPO_ROOT_PATH", "")
out = []
for key in keys:
    if key == pat_env_key and repo_root:
        cmd = f"{repo_root}/scripts/token_broker_e2e_cycle.sh __pat_check_env__ {key}"
    else:
        cmd = f'test -n "${{{key}:-}}"'
    if cmd not in out:
        out.append(cmd)
print("\n".join(out))
PY
}

next_action_ready_prereq_cmd_count_of() {
  local prereq_cmds_text="$1"
  count_nonempty_lines "$prereq_cmds_text"
}

next_action_execute_cmds_of() {
  local prereq_cmds_text="$1"
  local ready_cmds_text="$2"
  next_action_ready_cmds_of "$prereq_cmds_text" "$ready_cmds_text"
}

next_action_execute_cmd_count_of() {
  local execute_cmds_text="$1"
  count_nonempty_lines "$execute_cmds_text"
}

next_action_execute_cmd_blocker_of() {
  local execute_cmds_text="$1"
  next_action_cmd_blocker "$execute_cmds_text"
}

next_action_execute_cmd_auto_runnable_of() {
  local execute_cmds_text="$1"
  local blocker

  blocker="$(next_action_execute_cmd_blocker_of "$execute_cmds_text")"
  if [[ "$blocker" == "none" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

next_action_execute_env_ref_cmds_of() {
  local prereq_cmds_text="$1"
  local env_ref_cmds_text="$2"
  local pat_env_key="$3"
  local repo_root_path="$4"

  PREREQ_CMDS_TEXT="$prereq_cmds_text" \
  ENV_REF_CMDS_TEXT="$env_ref_cmds_text" \
  PAT_ENV_KEY_INPUT="$pat_env_key" \
  REPO_ROOT_PATH="$repo_root_path" \
  python3 - <<'PY'
import os

pre = [line.strip() for line in os.environ.get("PREREQ_CMDS_TEXT", "").splitlines() if line.strip()]
env = [line.strip() for line in os.environ.get("ENV_REF_CMDS_TEXT", "").splitlines() if line.strip()]
pat_env_key = os.environ.get("PAT_ENV_KEY_INPUT", "")
repo_root = os.environ.get("REPO_ROOT_PATH", "")

pat_marker = f"__pat_check_env__ {pat_env_key}" if pat_env_key else ""
canonical_pat_precheck = f"{repo_root}/scripts/token_broker_e2e_cycle.sh __pat_check_env__ {pat_env_key}" if (repo_root and pat_env_key) else ""
has_env_pat_precheck = bool(pat_marker) and any(pat_marker in line for line in env)

out = []
for line in pre:
    if has_env_pat_precheck and canonical_pat_precheck and line == canonical_pat_precheck:
        continue
    if line not in out:
        out.append(line)
for line in env:
    if line not in out:
        out.append(line)
print("\n".join(out))
PY
}

next_action_best_auto_cmd_source_of() {
  local execute_env_ref_auto="$1"
  local execute_auto="$2"
  local ready_auto="$3"

  if [[ "$execute_env_ref_auto" == "1" ]]; then
    echo "execute_env_ref"
    return
  fi
  if [[ "$execute_auto" == "1" ]]; then
    echo "execute"
    return
  fi
  if [[ "$ready_auto" == "1" ]]; then
    echo "ready"
    return
  fi
  echo "none"
}

next_action_best_auto_cmds_of() {
  local source="$1"
  local execute_env_ref_cmds="$2"
  local execute_cmds="$3"
  local ready_cmds="$4"

  case "$source" in
    execute_env_ref)
      echo "$execute_env_ref_cmds"
      ;;
    execute)
      echo "$execute_cmds"
      ;;
    ready)
      echo "$ready_cmds"
      ;;
    *)
      echo ""
      ;;
  esac
}

next_action_best_auto_cmd_blocker_of() {
  local best_auto_cmds_text="$1"
  next_action_cmd_blocker "$best_auto_cmds_text"
}

next_action_best_auto_cmd_auto_runnable_of() {
  local best_auto_cmds_text="$1"
  local blocker

  blocker="$(next_action_best_auto_cmd_blocker_of "$best_auto_cmds_text")"
  if [[ "$blocker" == "none" ]]; then
    echo "1"
  else
    echo "0"
  fi
}

next_action_best_auto_cmd_dispatch_mode_of() {
  local best_auto_cmd_auto_runnable="$1"
  local best_auto_cmd_blocker="$2"

  classify_next_action_dispatch_mode "$best_auto_cmd_auto_runnable" "0" "$best_auto_cmd_blocker"
}

next_action_requires_manual_input_of() {
  local template_var_count="$1"
  if [[ "${template_var_count:-0}" -gt 0 ]]; then
    echo "1"
  else
    echo "0"
  fi
}

classify_next_action_dispatch_mode() {
  local auto_runnable="$1"
  local manual_input="$2"
  local blocker="$3"

  if [[ "$auto_runnable" == "1" ]]; then
    echo "auto_runnable"
    return
  fi
  if [[ "$manual_input" == "1" ]]; then
    echo "manual_input_required"
    return
  fi
  if [[ "$blocker" == "no_steps" ]]; then
    echo "no_action"
    return
  fi
  if [[ -n "$blocker" && "$blocker" != "none" ]]; then
    echo "blocked:${blocker}"
    return
  fi
  echo "manual_review_required"
}

is_dummy_pat_value() {
  local v="$1"
  case "$v" in
    ""|"dummy"|"dummy-token"|"<valid_pat>"|"changeme"|"placeholder"|"example-token")
      return 0
      ;;
    ghu_dummy*|ghp_dummy*|github_pat_dummy*|dummy_*|test_pat_*|example_pat_*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_plausible_pat_shape() {
  local v="$1"
  local n=${#v}

  case "$v" in
    ghp_*|ghu_*|gho_*|ghs_*)
      [[ "$n" -ge 24 ]]
      return
      ;;
    github_pat_*)
      [[ "$n" -ge 40 ]]
      return
      ;;
    *)
      return 1
      ;;
  esac
}

detect_pat_shape_kind() {
  local v="$1"
  local n=${#v}

  if is_dummy_pat_value "$v"; then
    echo "dummy_placeholder"
    return
  fi

  case "$v" in
    "")
      echo "empty"
      ;;
    ghp_*|ghu_*|gho_*|ghs_*)
      if [[ "$n" -ge 24 ]]; then
        echo "classic_prefix"
      else
        echo "classic_prefix_too_short"
      fi
      ;;
    github_pat_*)
      if [[ "$n" -ge 40 ]]; then
        echo "fine_grained_prefix"
      else
        echo "fine_grained_prefix_too_short"
      fi
      ;;
    *)
      echo "unknown_prefix"
      ;;
  esac
}

is_valid_pat_kind() {
  local kind="$1"
  case "$kind" in
    classic_prefix|fine_grained_prefix)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

check_pat_value() {
  local value="$1"
  local kind len
  kind="$(detect_pat_shape_kind "$value")"
  len=${#value}
  if is_valid_pat_kind "$kind"; then
    echo "PAT_CHECK_OK kind=${kind} len=${len}"
    return 0
  fi
  echo "PAT_CHECK_FAIL kind=${kind} len=${len}"
  return 2
}

check_pat_env() {
  local env_key="$1"
  if [[ -z "$env_key" ]]; then
    echo "PAT_CHECK_FAIL reason=missing_env_key"
    return 2
  fi
  if [[ -z "${!env_key+x}" ]]; then
    echo "PAT_CHECK_FAIL reason=env_not_set env_key=${env_key}"
    return 2
  fi

  local value out rc
  value="${!env_key}"
  set +e
  out="$(check_pat_value "$value" 2>&1)"
  rc=$?
  set -e
  echo "${out} env_key=${env_key}"
  return $rc
}

resolve_auto_run_blocker_code() {
  local injected="$1"
  local precheck_failed_flag="$2"
  local classification="$3"

  if [[ "$injected" == "1" ]]; then
    echo "dummy_pat_injected"
    return
  fi
  if [[ "${pat_detected_dummy:-0}" == "1" ]]; then
    echo "dummy_pat_detected"
    return
  fi
  if [[ "${pat_shape_invalid:-0}" == "1" ]]; then
    echo "pat_shape_invalid"
    return
  fi
  if [[ "${http_audit_mismatch:-0}" == "1" ]]; then
    echo "http_audit_mismatch"
    return
  fi
  if [[ "$precheck_failed_flag" == "1" ]]; then
    echo "precheck_failed"
    return
  fi
  if [[ "$classification" == "needs_manual_review" ]]; then
    echo "manual_review_required"
    return
  fi
  echo ""
}

is_allowed_validator_action() {
  local action="$1"
  case "$action" in
    none|fix_cli_invocation|provide_valid_jsonl_path|regenerate_selftest_jsonl|upgrade_consumer_schema|upgrade_validator|investigate_selftest_failures|inspect_validator_output)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

emit_self_test_case() {
  local format="$1"
  local case_id="$2"
  local name="$3"
  local pass="$4"
  local got="$5"
  local want="$6"

  if [[ "$format" == "json" ]]; then
    TEST_CASE_ID="$case_id" TEST_NAME="$name" TEST_PASS="$pass" TEST_GOT="$got" TEST_WANT="$want" TEST_SCHEMA_VERSION="$SELFTEST_SCHEMA_VERSION" python3 - <<'PY'
import json
import os
print(json.dumps({
  "type": "case",
  "schema_version": os.environ.get("TEST_SCHEMA_VERSION", ""),
  "case_id": os.environ.get("TEST_CASE_ID", ""),
  "name": os.environ.get("TEST_NAME", ""),
  "pass": os.environ.get("TEST_PASS", "0") == "1",
  "got": os.environ.get("TEST_GOT", ""),
  "want": os.environ.get("TEST_WANT", ""),
}, ensure_ascii=False))
PY
    return
  fi

  if [[ "$pass" == "1" ]]; then
    echo "SELF_TEST_CASE PASS [${case_id}] ${name}"
  else
    echo "SELF_TEST_CASE FAIL [${case_id}] ${name}: got='${got}' want='${want}'"
  fi
}

emit_self_test_summary() {
  local format="$1"
  local total="$2"
  local failed="$3"

  if [[ "$format" == "json" ]]; then
    SUMMARY_TOTAL="$total" SUMMARY_FAILED="$failed" SUMMARY_SCHEMA_VERSION="$SELFTEST_SCHEMA_VERSION" SUMMARY_COMPAT_MIN_SCHEMA="$SELFTEST_COMPAT_MIN_SCHEMA" SUMMARY_VALIDATOR_VERSION="$VALIDATOR_VERSION" SUMMARY_COMPAT_MIN_VALIDATOR="$VALIDATOR_COMPAT_MIN_VERSION" python3 - <<'PY'
import json
import os
failed = int(os.environ.get("SUMMARY_FAILED", "0") or "0")
print(json.dumps({
  "type": "summary",
  "schema_version": os.environ.get("SUMMARY_SCHEMA_VERSION", ""),
  "compat_min_schema": os.environ.get("SUMMARY_COMPAT_MIN_SCHEMA", ""),
  "validator_version": os.environ.get("SUMMARY_VALIDATOR_VERSION", ""),
  "compat_min_validator_version": os.environ.get("SUMMARY_COMPAT_MIN_VALIDATOR", ""),
  "total": int(os.environ.get("SUMMARY_TOTAL", "0") or "0"),
  "failed": failed,
  "pass": failed == 0,
}, ensure_ascii=False))
PY
    return
  fi

  if [[ "$failed" -gt 0 ]]; then
    echo "SELF_TEST_RESULT FAIL count=$failed total=$total"
  else
    echo "SELF_TEST_RESULT PASS total=$total"
  fi
}

verify_validate_checksum_line() {
  local line="$1"
  VALIDATE_LINE="$line" python3 - <<'PY' >/dev/null
import hashlib
import os
import sys

line = (os.environ.get("VALIDATE_LINE") or "").strip()
if not line:
    sys.exit(1)

tokens = line.split()
if len(tokens) < 2:
    sys.exit(2)

ordered = []
values = {}
for tok in tokens[1:]:
    if "=" not in tok:
        continue
    k, v = tok.split("=", 1)
    ordered.append((k, v))
    values[k] = v

required = [
    "result_code",
    "error_code",
    "action",
    "validator_version",
    "checksum_verify_mode",
    "checksum_algo",
    "checksum_scope_version",
    "checksum_scope",
    "kv_checksum",
]
for key in required:
    if key not in values:
        sys.exit(3)

if values["checksum_algo"] != "sha256-16":
    sys.exit(4)

scope_by_version = {
    "v1": "result_code,error_code,action,validator_version,extras",
}
scope_version = values["checksum_scope_version"]
if scope_version not in scope_by_version:
    sys.exit(5)
if values["checksum_scope"] != scope_by_version[scope_version]:
    sys.exit(6)

checksum_parts = [
    f"result_code={values['result_code']}",
    f"error_code={values['error_code']}",
    f"action={values['action']}",
    f"validator_version={values['validator_version']}",
]
for key, val in ordered:
    if key in {
        "result_code",
        "error_code",
        "action",
        "validator_version",
        "checksum_algo",
        "checksum_scope_version",
        "checksum_scope",
        "kv_checksum",
    }:
        continue
    checksum_parts.append(f"{key}={val}")

digest = hashlib.sha256("|".join(checksum_parts).encode("utf-8")).hexdigest()[:16]
if digest != values["kv_checksum"]:
    sys.exit(7)
PY
}

emit_validator_fail_line() {
  local error_code="$1"
  local checksum_verify_mode="${2:-verify}"
  shift 2 || true

  local extras_joined=""
  local arg=""
  for arg in "$@"; do
    if [[ -n "$extras_joined" ]]; then
      extras_joined+=$'\x1f'
    fi
    extras_joined+="$arg"
  done

  VALIDATOR_VERSION="$VALIDATOR_VERSION" ERROR_CODE="$error_code" CHECKSUM_VERIFY_MODE="$checksum_verify_mode" EXTRAS_JOINED="$extras_joined" python3 - <<'PY'
import hashlib
import os
import urllib.parse

validator_version = os.environ.get("VALIDATOR_VERSION", "")
error_code = os.environ.get("ERROR_CODE", "")
checksum_verify_mode = os.environ.get("CHECKSUM_VERIFY_MODE", "verify") or "verify"
raw_extras = os.environ.get("EXTRAS_JOINED", "")
extras = [x for x in raw_extras.split("\x1f") if x]

def normalize_extra(token: str) -> str:
    if "=" not in token:
        canonical = urllib.parse.quote(urllib.parse.unquote(token), safe='-._~:/=@')
        return f"extra={canonical}"
    key, value = token.split("=", 1)
    canonical = urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@')
    return f"{key}={canonical}"

extras = [normalize_extra(x) for x in extras]

action_map = {
    "missing_file_path": "fix_cli_invocation",
    "file_not_found": "provide_valid_jsonl_path",
    "empty_jsonl": "regenerate_selftest_jsonl",
    "invalid_json": "regenerate_selftest_jsonl",
    "missing_summary": "regenerate_selftest_jsonl",
    "schema_too_old": "upgrade_consumer_schema",
    "validator_too_old": "upgrade_validator",
    "summary_pass_false": "investigate_selftest_failures",
    "invalid_action_enum": "inspect_validator_output",
    "invalid_checksum_mode": "fix_cli_invocation",
    "unexpected_extra_args": "fix_cli_invocation",
    "checksum_verify_failed": "inspect_validator_output",
}
action = action_map.get(error_code, "inspect_validator_output")

parts = [
    "result_code=validate_failed",
    f"error_code={error_code}",
    f"action={action}",
    f"validator_version={validator_version}",
    f"checksum_verify_mode={checksum_verify_mode}",
]
parts.extend(extras)
checksum = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
parts.append("checksum_algo=sha256-16")
parts.append("checksum_scope_version=v1")
parts.append("checksum_scope=result_code,error_code,action,validator_version,extras")
parts.append(f"kv_checksum={checksum}")
print("SELF_TEST_JSON_VALIDATE_FAIL " + " ".join(parts))
PY
}

run_self_tests() {
  local format="${1:-text}"
  local failed=0
  local total=0

  run_case() {
    local case_id="$1"
    local name="$2"
    local got="$3"
    local want="$4"
    total=$((total + 1))
    if [[ "$got" == "$want" ]]; then
      emit_self_test_case "$format" "$case_id" "$name" "1" "$got" "$want"
    else
      failed=$((failed + 1))
      emit_self_test_case "$format" "$case_id" "$name" "0" "$got" "$want"
    fi
  }

  local blocker_cases
  blocker_cases=$(cat <<'EOF'
B01|priority_dummy_over_all|1|1|needs_manual_review|dummy_pat_injected
B02|priority_precheck_over_manual|0|1|needs_manual_review|precheck_failed
B03|manual_review_when_no_other_blocker|0|0|needs_manual_review|manual_review_required
B04|no_blocker_for_success|0|0|exchange_success|
EOF
)

  while IFS='|' read -r case_id name injected precheck_fail_flag cls want; do
    [[ -z "$name" ]] && continue
    run_case "$case_id" "$name" "$(resolve_auto_run_blocker_code "$injected" "$precheck_fail_flag" "$cls")" "$want"
  done <<<"$blocker_cases"

  pat_detected_dummy=1
  run_case "B05" "dummy_pat_detected_when_not_injected" "$(resolve_auto_run_blocker_code "0" "0" "exchange_success")" "dummy_pat_detected"
  pat_detected_dummy=0

  http_audit_mismatch=1
  run_case "B06" "http_audit_mismatch_blocks_auto_run" "$(resolve_auto_run_blocker_code "0" "0" "exchange_success")" "http_audit_mismatch"
  http_audit_mismatch=0

  pat_shape_invalid=1
  run_case "B07" "invalid_pat_shape_blocks_auto_run" "$(resolve_auto_run_blocker_code "0" "0" "exchange_success")" "pat_shape_invalid"
  pat_shape_invalid=0

  if is_plausible_pat_shape "ghp_abcdefghijklmnopqrstuvwxyz"; then
    run_case "B08" "pat_shape_accepts_classic_ghp" "1" "1"
  else
    run_case "B08" "pat_shape_accepts_classic_ghp" "0" "1"
  fi
  if is_plausible_pat_shape "abc12345"; then
    run_case "B09" "pat_shape_rejects_plain_string" "0" "1"
  else
    run_case "B09" "pat_shape_rejects_plain_string" "1" "1"
  fi

  if should_skip_precheck "rotate_or_fix_pat" "1"; then
    run_case "B10" "skip_precheck_when_dummy_injected" "1" "1"
  else
    run_case "B10" "skip_precheck_when_dummy_injected" "0" "1"
  fi
  if should_skip_precheck "rotate_or_fix_pat" "0"; then
    run_case "B11" "do_not_skip_precheck_for_real_pat" "0" "1"
  else
    run_case "B11" "do_not_skip_precheck_for_real_pat" "1" "1"
  fi

  run_case "B12" "effective_precheck_steps_zero_when_skipped" "$(effective_precheck_steps "1" "dummy_pat_injected")" "0"
  run_case "B13" "effective_precheck_steps_keep_total_when_not_skipped" "$(effective_precheck_steps "1" "")" "1"
  run_case "B14" "pat_shape_kind_classic_prefix" "$(detect_pat_shape_kind "ghp_abcdefghijklmnopqrstuvwxyz")" "classic_prefix"
  run_case "B15" "pat_shape_kind_fine_grained_prefix" "$(detect_pat_shape_kind "github_pat_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")" "fine_grained_prefix"
  run_case "B16" "pat_shape_kind_unknown_prefix" "$(detect_pat_shape_kind "abc12345")" "unknown_prefix"
  if check_pat_value "ghp_abcdefghijklmnopqrstuvwxyz" >/dev/null 2>&1; then
    run_case "B17" "check_pat_value_accepts_valid_classic" "1" "1"
  else
    run_case "B17" "check_pat_value_accepts_valid_classic" "0" "1"
  fi
  if check_pat_value "dummy-token" >/dev/null 2>&1; then
    run_case "B18" "check_pat_value_rejects_dummy" "0" "1"
  else
    run_case "B18" "check_pat_value_rejects_dummy" "1" "1"
  fi

  local out_pat_env
  if out_pat_env="$(CELLA_TMP_PAT=dummy-token check_pat_env CELLA_TMP_PAT 2>&1)"; then
    run_case "B19" "check_pat_env_rejects_dummy" "0" "1"
  elif [[ "$out_pat_env" == PAT_CHECK_FAIL* ]]; then
    run_case "B19" "check_pat_env_rejects_dummy" "1" "1"
  else
    run_case "B19" "check_pat_env_rejects_dummy" "0" "1"
  fi

  run_precheck_commands $'true\nfalse'
  run_case "P01" "precheck_fail_flag_set" "$precheck_failed" "1"
  if [[ "$precheck_failed_cmds" == *"false"* ]]; then
    run_case "P02" "precheck_failed_cmds_contains_false" "1" "1"
  else
    run_case "P02" "precheck_failed_cmds_contains_false" "0" "1"
  fi

  run_precheck_commands $'echo precheck-boom >&2; false'
  if [[ "$precheck_failed_outputs" == *"precheck-boom"* ]]; then
    run_case "P03" "precheck_failed_outputs_capture_last_line" "1" "1"
  else
    run_case "P03" "precheck_failed_outputs_capture_last_line" "0" "1"
  fi
  if [[ "$precheck_failed_rcs" == *"rc=1"* ]]; then
    run_case "P04" "precheck_failed_rcs_capture_exit_code" "1" "1"
  else
    run_case "P04" "precheck_failed_rcs_capture_exit_code" "0" "1"
  fi

  run_precheck_commands $'echo PAT_CHECK_FAIL kind=simulated len=1 >&2; exit 2'
  if [[ "$precheck_failed_kinds" == *"simulated"* ]]; then
    run_case "P05" "precheck_failed_kinds_capture_pat_kind" "1" "1"
  else
    run_case "P05" "precheck_failed_kinds_capture_pat_kind" "0" "1"
  fi

  run_case "P15" "extract_kind_prefers_pat_check_line" "$(extract_kind_from_output $'noise\nPAT_CHECK_FAIL kind=alpha len=1\nextra kind=beta')" "alpha"
  run_case "P16" "extract_kind_empty_when_missing" "$(extract_kind_from_output 'plain line without token')" ""

  run_case "P06" "classify_precheck_none" "$(classify_precheck_failure "" "0" "" "")" "none"
  run_case "P07" "classify_precheck_skipped" "$(classify_precheck_failure "dummy_pat_injected" "0" "" "")" "skipped:dummy_pat_injected"
  run_case "P08" "classify_precheck_dummy_kind" "$(classify_precheck_failure "" "1" "x => dummy_placeholder" "x => rc=2")" "pat_dummy_placeholder"
  run_case "P09" "classify_precheck_shape_kind" "$(classify_precheck_failure "" "1" "x => unknown_prefix" "x => rc=2")" "pat_shape_invalid"
  run_case "P10" "classify_precheck_cmd_not_found" "$(classify_precheck_failure "" "1" "" "x => rc=127")" "precheck_cmd_not_found"

  run_case "P11" "classify_cycle_outcome_blocked" "$(classify_cycle_outcome "dummy_pat_detected" "upstream_reject_after_broker_replace")" "blocked:dummy_pat_detected"
  run_case "P12" "classify_cycle_outcome_success" "$(classify_cycle_outcome "" "exchange_success")" "success"
  run_case "P13" "classify_cycle_outcome_upstream_reject" "$(classify_cycle_outcome "" "upstream_reject_after_broker_replace")" "upstream_reject_after_replace"
  run_case "P14" "classify_cycle_outcome_manual_review" "$(classify_cycle_outcome "" "needs_manual_review")" "manual_review"
  run_case "P91" "classify_goal_state_success" "$(classify_goal_state "success")" "success"
  run_case "P92" "classify_goal_state_broker_path_active" "$(classify_goal_state "broker_path_active")" "broker_path_active"
  run_case "P93" "classify_goal_state_not_reached" "$(classify_goal_state "upstream_reject_after_replace")" "not_reached"
  run_case "P94" "goal_state_reached_flag" "$(goal_state_reached_of "success")" "1"
  run_case "P95" "goal_state_not_reached_flag" "$(goal_state_reached_of "not_reached")" "0"
  run_case "P96" "next_action_best_auto_cmd_dispatch_mode_auto_runnable" "$(next_action_best_auto_cmd_dispatch_mode_of 1 none)" "auto_runnable"
  run_case "P97" "next_action_best_auto_cmd_dispatch_mode_no_action" "$(next_action_best_auto_cmd_dispatch_mode_of 0 no_steps)" "no_action"
  run_case "P98" "next_action_best_auto_cmd_dispatch_mode_blocked" "$(next_action_best_auto_cmd_dispatch_mode_of 0 templated_pat)" "blocked:templated_pat"
  run_case "P17" "classify_next_action_dummy_block" "$(classify_next_action "blocked:dummy_pat_detected" "pat_dummy_placeholder" "rotate_or_fix_pat")" "provide_real_pat"
  run_case "P18" "classify_next_action_shape_block" "$(classify_next_action "blocked:pat_shape_invalid" "pat_shape_invalid" "rotate_or_fix_pat")" "provide_valid_pat_shape"
  run_case "P19" "classify_next_action_upstream_reject" "$(classify_next_action "upstream_reject_after_replace" "none" "rotate_or_fix_pat")" "rotate_or_fix_pat"
  run_case "P20" "classify_next_action_success" "$(classify_next_action "success" "none" "keep_current_config")" "run_inference_smoke"

  if [[ "$(next_action_cmd_for_next_action "provide_real_pat")" == *"__pat_check_env__"* ]]; then
    run_case "P21" "next_action_cmd_real_pat_contains_pat_check" "1" "1"
  else
    run_case "P21" "next_action_cmd_real_pat_contains_pat_check" "0" "1"
  fi
  if [[ "$(next_action_cmd_for_next_action "run_inference_smoke")" == *"./scripts/token_broker_e2e_cycle.sh"* ]]; then
    run_case "P22" "next_action_cmd_inference_smoke_contains_e2e_cmd" "1" "1"
  else
    run_case "P22" "next_action_cmd_inference_smoke_contains_e2e_cmd" "0" "1"
  fi
  run_case "P23" "next_action_cmd_real_pat_has_two_steps" "$(count_nonempty_lines "$(next_action_cmd_for_next_action "provide_real_pat")")" "2"
  run_case "P24" "next_action_cmd_inference_has_one_step" "$(count_nonempty_lines "$(next_action_cmd_for_next_action "run_inference_smoke")")" "1"
  run_case "P25" "next_action_cmd_auto_runnable_false_for_template" "$(next_action_cmd_auto_runnable "$(next_action_cmd_for_next_action "provide_real_pat")")" "0"
  run_case "P26" "next_action_cmd_auto_runnable_true_for_smoke" "$(next_action_cmd_auto_runnable "$(next_action_cmd_for_next_action "run_inference_smoke")")" "1"
  run_case "P27" "next_action_cmd_blocker_template" "$(next_action_cmd_blocker "$(next_action_cmd_for_next_action "provide_real_pat")")" "templated_pat"
  run_case "P28" "next_action_cmd_blocker_none" "$(next_action_cmd_blocker "$(next_action_cmd_for_next_action "run_inference_smoke")")" "none"
  run_case "P29" "next_action_cmd_hash_empty_when_no_steps" "$(next_action_cmd_hash_of '')" ""
  if [[ "$(next_action_cmd_hash_of 'echo hi')" == "$(next_action_cmd_hash_of 'echo hi')" ]]; then
    run_case "P30" "next_action_cmd_hash_stable" "1" "1"
  else
    run_case "P30" "next_action_cmd_hash_stable" "0" "1"
  fi
  if [[ "$(next_action_cmd_hash_of 'echo hi')" == "$(next_action_cmd_hash_of 'echo bye')" ]]; then
    run_case "P31" "next_action_cmd_hash_changes_with_content" "0" "1"
  else
    run_case "P31" "next_action_cmd_hash_changes_with_content" "1" "1"
  fi
  run_case "P32" "next_action_template_vars_extracts_valid_pat" "$(next_action_template_vars_of 'echo <valid_pat> and <valid_pat>')" "<valid_pat>"
  run_case "P33" "next_action_template_var_count" "$(next_action_template_var_count_of "$(next_action_template_vars_of 'echo <a> <b> <a>')")" "2"
  run_case "P34" "next_action_requires_manual_input_true" "$(next_action_requires_manual_input_of 1)" "1"
  run_case "P35" "next_action_requires_manual_input_false" "$(next_action_requires_manual_input_of 0)" "0"
  run_case "P36" "next_action_dispatch_mode_auto_runnable" "$(classify_next_action_dispatch_mode 1 0 none)" "auto_runnable"
  run_case "P37" "next_action_dispatch_mode_manual_input_required" "$(classify_next_action_dispatch_mode 0 1 templated_pat)" "manual_input_required"
  run_case "P38" "next_action_dispatch_mode_no_action" "$(classify_next_action_dispatch_mode 0 0 no_steps)" "no_action"
  run_case "P39" "next_action_dispatch_mode_blocked" "$(classify_next_action_dispatch_mode 0 0 templated_pat)" "blocked:templated_pat"
  run_case "P40" "next_action_missing_inputs_extract" "$(next_action_missing_inputs_of "$(next_action_template_vars_of 'x <valid_pat> y <target_container> z')")" $'valid_pat\ntarget_container'
  run_case "P41" "next_action_missing_inputs_count" "$(next_action_missing_input_count_of "$(next_action_missing_inputs_of '<a>
<b>
<a>')")" "2"
  run_case "P42" "next_action_missing_inputs_empty" "$(next_action_missing_inputs_of '')" ""
  run_case "P43" "next_action_missing_input_env_keys_mapped" "$(next_action_missing_input_env_keys_of 'valid_pat
target_container')" $'CELLA_BROKER_TEST_PAT
CELLA_BROKER_TEST_CONTAINER'
  run_case "P44" "next_action_missing_input_env_keys_ignores_unknown" "$(next_action_missing_input_env_keys_of 'unknown_input')" ""
  run_case "P45" "next_action_missing_input_env_key_count" "$(next_action_missing_input_env_key_count_of "$(next_action_missing_input_env_keys_of 'valid_pat
unknown_input')")" "1"
  p46_export_cmds="$(next_action_missing_input_export_cmds_of "$(next_action_missing_input_env_keys_of 'valid_pat
target_container')")"
  if [[ "$p46_export_cmds" == *"export CELLA_BROKER_TEST_PAT='<valid_pat>'"* ]] && [[ "$p46_export_cmds" == *"export CELLA_BROKER_TEST_CONTAINER='<container_name>'"* ]]; then
    run_case "P46" "next_action_missing_input_export_cmds_mapped" "1" "1"
  else
    run_case "P46" "next_action_missing_input_export_cmds_mapped" "0" "1"
  fi
  run_case "P47" "next_action_missing_input_export_cmd_count" "$(next_action_missing_input_export_cmd_count_of "$(next_action_missing_input_export_cmds_of 'CELLA_BROKER_TEST_PAT
CELLA_BROKER_TEST_PAT')")" "1"
  run_case "P48" "next_action_missing_input_export_cmds_empty" "$(next_action_missing_input_export_cmds_of '')" ""
  p49_env_ref_cmds="$(next_action_env_ref_cmds_of "$(next_action_cmd_for_next_action 'provide_real_pat')")"
  if [[ "$p49_env_ref_cmds" == *"${PAT_ENV_KEY}=\${CELLA_BROKER_TEST_PAT} ${repo_root}/scripts/token_broker_e2e_cycle.sh __pat_check_env__ ${PAT_ENV_KEY}"* ]] && [[ "$p49_env_ref_cmds" == *"${PAT_ENV_KEY}=\${CELLA_BROKER_TEST_PAT} ./scripts/token_broker_e2e_cycle.sh ${CONTAINER}"* ]]; then
    run_case "P49" "next_action_env_ref_cmds_replaces_valid_pat" "1" "1"
  else
    run_case "P49" "next_action_env_ref_cmds_replaces_valid_pat" "0" "1"
  fi
  run_case "P50" "next_action_env_ref_cmds_preserves_plain_text" "$(next_action_env_ref_cmds_of 'echo ok')" "echo ok"
  run_case "P51" "next_action_env_ref_cmd_count" "$(next_action_env_ref_cmd_count_of "$(next_action_env_ref_cmds_of "$(next_action_cmd_for_next_action 'provide_real_pat')")")" "2"
  if [[ "$(next_action_env_ref_cmds_of 'echo <valid_pat>')" == *"<valid_pat>"* ]]; then
    run_case "P52" "next_action_env_ref_cmds_no_raw_placeholder" "0" "1"
  else
    run_case "P52" "next_action_env_ref_cmds_no_raw_placeholder" "1" "1"
  fi
  p53_ready_cmds="$(next_action_ready_cmds_of "$(next_action_missing_input_export_cmds_of 'CELLA_BROKER_TEST_PAT')" "$(next_action_env_ref_cmds_of "$(next_action_cmd_for_next_action 'provide_real_pat')")")"
  if [[ "$p53_ready_cmds" == *"export CELLA_BROKER_TEST_PAT='<valid_pat>'"* ]] && [[ "$p53_ready_cmds" == *"${PAT_ENV_KEY}=\${CELLA_BROKER_TEST_PAT} ./scripts/token_broker_e2e_cycle.sh ${CONTAINER}"* ]]; then
    run_case "P53" "next_action_ready_cmds_contains_export_and_run" "1" "1"
  else
    run_case "P53" "next_action_ready_cmds_contains_export_and_run" "0" "1"
  fi
  run_case "P54" "next_action_ready_cmd_count_dedup" "$(next_action_ready_cmd_count_of "$(next_action_ready_cmds_of 'export X=1
export X=1' 'echo ok')")" "2"
  run_case "P55" "next_action_ready_cmds_empty" "$(next_action_ready_cmds_of '' '')" ""
  run_case "P56" "next_action_missing_secret_env_keys_detect_pat" "$(next_action_missing_secret_env_keys_of 'CELLA_BROKER_TEST_PAT
CELLA_BROKER_TEST_CONTAINER')" "CELLA_BROKER_TEST_PAT"
  run_case "P57" "next_action_missing_secret_env_key_count" "$(next_action_missing_secret_env_key_count_of "$(next_action_missing_secret_env_keys_of 'CELLA_BROKER_TEST_PAT
CELLA_BROKER_TEST_CONTAINER')")" "1"
  run_case "P58" "next_action_missing_secret_env_keys_empty" "$(next_action_missing_secret_env_keys_of 'CELLA_BROKER_TEST_CONTAINER')" ""
  run_case "P59" "next_action_ready_cmd_hash_empty_when_no_ready_cmds" "$(next_action_cmd_hash_of '')" ""
  if [[ "$(next_action_cmd_hash_of "$(next_action_ready_cmds_of 'export X=1' 'echo ok')")" == "$(next_action_cmd_hash_of "$(next_action_ready_cmds_of 'export X=1' 'echo ok')")" ]]; then
    run_case "P60" "next_action_ready_cmd_hash_stable" "1" "1"
  else
    run_case "P60" "next_action_ready_cmd_hash_stable" "0" "1"
  fi
  if [[ "$(next_action_cmd_hash_of "$(next_action_ready_cmds_of 'export X=1' 'echo ok')")" == "$(next_action_cmd_hash_of "$(next_action_ready_cmds_of 'export X=2' 'echo ok')")" ]]; then
    run_case "P61" "next_action_ready_cmd_hash_changes_with_content" "0" "1"
  else
    run_case "P61" "next_action_ready_cmd_hash_changes_with_content" "1" "1"
  fi
  run_case "P62" "next_action_ready_cmd_blocker_no_steps" "$(next_action_ready_cmd_blocker_of '')" "no_steps"
  run_case "P63" "next_action_ready_cmd_blocker_templated" "$(next_action_ready_cmd_blocker_of "$(next_action_ready_cmds_of "export CELLA_BROKER_TEST_PAT='<valid_pat>'" 'echo ok')")" "templated_pat"
  run_case "P64" "next_action_ready_cmd_auto_runnable_false_when_templated" "$(next_action_ready_cmd_auto_runnable_of "$(next_action_ready_cmds_of "export CELLA_BROKER_TEST_PAT='<valid_pat>'" 'echo ok')")" "0"
  run_case "P65" "next_action_ready_cmd_auto_runnable_true_when_plain" "$(next_action_ready_cmd_auto_runnable_of "$(next_action_ready_cmds_of '' 'echo ok')")" "1"
  if [[ "$(next_action_ready_prereq_cmds_of 'CELLA_BROKER_TEST_PAT' "$PAT_ENV_KEY" "$repo_root")" == *"__pat_check_env__ CELLA_BROKER_TEST_PAT"* ]]; then
    run_case "P66" "next_action_ready_prereq_cmds_pat_uses_pat_check" "1" "1"
  else
    run_case "P66" "next_action_ready_prereq_cmds_pat_uses_pat_check" "0" "1"
  fi
  run_case "P67" "next_action_ready_prereq_cmd_count_dedup" "$(next_action_ready_prereq_cmd_count_of "$(next_action_ready_prereq_cmds_of 'CELLA_BROKER_TEST_PAT
CELLA_BROKER_TEST_PAT' "$PAT_ENV_KEY" "$repo_root")")" "1"
  run_case "P68" "next_action_ready_prereq_cmds_empty" "$(next_action_ready_prereq_cmds_of '' "$PAT_ENV_KEY" "$repo_root")" ""
  run_case "P69" "next_action_ready_prereq_cmd_hash_empty_when_no_cmds" "$(next_action_cmd_hash_of '')" ""
  if [[ "$(next_action_cmd_hash_of "$(next_action_ready_prereq_cmds_of 'CELLA_BROKER_TEST_PAT' "$PAT_ENV_KEY" "$repo_root")")" == "$(next_action_cmd_hash_of "$(next_action_ready_prereq_cmds_of 'CELLA_BROKER_TEST_PAT' "$PAT_ENV_KEY" "$repo_root")")" ]]; then
    run_case "P70" "next_action_ready_prereq_cmd_hash_stable" "1" "1"
  else
    run_case "P70" "next_action_ready_prereq_cmd_hash_stable" "0" "1"
  fi
  if [[ "$(next_action_cmd_hash_of "$(next_action_ready_prereq_cmds_of 'CELLA_BROKER_TEST_PAT' "$PAT_ENV_KEY" "$repo_root")")" == "$(next_action_cmd_hash_of "$(next_action_ready_prereq_cmds_of 'CELLA_BROKER_TEST_PAT
CELLA_BROKER_TEST_TOKEN' "$PAT_ENV_KEY" "$repo_root")")" ]]; then
    run_case "P71" "next_action_ready_prereq_cmd_hash_changes_with_content" "0" "1"
  else
    run_case "P71" "next_action_ready_prereq_cmd_hash_changes_with_content" "1" "1"
  fi
  run_case "P72" "next_action_execute_cmd_count_combines_prereq_and_ready" "$(next_action_execute_cmd_count_of "$(next_action_execute_cmds_of 'precheck A' 'run B')")" "2"
  run_case "P73" "next_action_execute_cmd_blocker_templated" "$(next_action_execute_cmd_blocker_of "$(next_action_execute_cmds_of 'precheck A' "export CELLA_BROKER_TEST_PAT='<valid_pat>'")")" "templated_pat"
  run_case "P74" "next_action_execute_cmd_auto_runnable_true" "$(next_action_execute_cmd_auto_runnable_of "$(next_action_execute_cmds_of 'precheck A' 'run B')")" "1"
  run_case "P75" "next_action_execute_cmd_auto_runnable_false" "$(next_action_execute_cmd_auto_runnable_of "$(next_action_execute_cmds_of 'precheck A' "export CELLA_BROKER_TEST_PAT='<valid_pat>'")")" "0"
  run_case "P76" "next_action_execute_env_ref_cmd_count" "$(next_action_execute_cmd_count_of "$(next_action_execute_env_ref_cmds_of 'precheck A' 'CELLA_BROKER_TEST_PAT=${CELLA_BROKER_TEST_PAT} run B' "$PAT_ENV_KEY" "$repo_root")")" "2"
  run_case "P77" "next_action_execute_env_ref_cmd_blocker_none" "$(next_action_execute_cmd_blocker_of "$(next_action_execute_env_ref_cmds_of 'precheck A' 'CELLA_BROKER_TEST_PAT=${CELLA_BROKER_TEST_PAT} run B' "$PAT_ENV_KEY" "$repo_root")")" "none"
  run_case "P78" "next_action_execute_env_ref_cmd_auto_runnable_true" "$(next_action_execute_cmd_auto_runnable_of "$(next_action_execute_env_ref_cmds_of 'precheck A' 'CELLA_BROKER_TEST_PAT=${CELLA_BROKER_TEST_PAT} run B' "$PAT_ENV_KEY" "$repo_root")")" "1"
  if [[ "$(next_action_cmd_hash_of "$(next_action_execute_env_ref_cmds_of 'precheck A' 'CELLA_BROKER_TEST_PAT=${CELLA_BROKER_TEST_PAT} run B' "$PAT_ENV_KEY" "$repo_root")")" == "$(next_action_cmd_hash_of "$(next_action_execute_env_ref_cmds_of 'precheck A' 'CELLA_BROKER_TEST_PAT=${CELLA_BROKER_TEST_PAT} run B' "$PAT_ENV_KEY" "$repo_root")")" ]]; then
    run_case "P79" "next_action_execute_env_ref_cmd_hash_stable" "1" "1"
  else
    run_case "P79" "next_action_execute_env_ref_cmd_hash_stable" "0" "1"
  fi
  p89_prereq_cmd="$repo_root/scripts/token_broker_e2e_cycle.sh __pat_check_env__ $PAT_ENV_KEY"
  p89_env_cmds="$PAT_ENV_KEY=\${CELLA_BROKER_TEST_PAT} $repo_root/scripts/token_broker_e2e_cycle.sh __pat_check_env__ $PAT_ENV_KEY
$PAT_ENV_KEY=\${CELLA_BROKER_TEST_PAT} ./scripts/token_broker_e2e_cycle.sh $CONTAINER"
  run_case "P89" "next_action_execute_env_ref_cmds_drop_duplicate_pat_precheck" "$(next_action_execute_cmd_count_of "$(next_action_execute_env_ref_cmds_of "$p89_prereq_cmd" "$p89_env_cmds" "$PAT_ENV_KEY" "$repo_root")")" "2"
  run_case "P90" "next_action_execute_env_ref_cmds_keep_nonoverlap_prereq" "$(next_action_execute_cmd_count_of "$(next_action_execute_env_ref_cmds_of 'test -n "${X:-}"' "$p89_env_cmds" "$PAT_ENV_KEY" "$repo_root")")" "3"
  run_case "P80" "next_action_best_auto_cmd_source_prefers_env_ref" "$(next_action_best_auto_cmd_source_of 1 1 1)" "execute_env_ref"
  run_case "P81" "next_action_best_auto_cmd_source_falls_back_execute" "$(next_action_best_auto_cmd_source_of 0 1 1)" "execute"
  run_case "P82" "next_action_best_auto_cmd_source_falls_back_ready" "$(next_action_best_auto_cmd_source_of 0 0 1)" "ready"
  run_case "P83" "next_action_best_auto_cmd_source_none" "$(next_action_best_auto_cmd_source_of 0 0 0)" "none"
  run_case "P84" "next_action_best_auto_cmds_uses_execute_env_ref" "$(next_action_best_auto_cmds_of 'execute_env_ref' 'envref run' 'execute run' 'ready run')" "envref run"
  run_case "P85" "next_action_best_auto_cmds_empty_for_none" "$(next_action_best_auto_cmds_of 'none' 'envref run' 'execute run' 'ready run')" ""
  run_case "P86" "next_action_best_auto_cmd_blocker_none" "$(next_action_best_auto_cmd_blocker_of "$(next_action_best_auto_cmds_of 'execute_env_ref' 'envref run' 'execute run' 'ready run')")" "none"
  run_case "P87" "next_action_best_auto_cmd_auto_runnable_true" "$(next_action_best_auto_cmd_auto_runnable_of "$(next_action_best_auto_cmds_of 'execute_env_ref' 'envref run' 'execute run' 'ready run')")" "1"
  run_case "P88" "next_action_best_auto_cmd_blocker_no_steps" "$(next_action_best_auto_cmd_blocker_of "$(next_action_best_auto_cmds_of 'none' 'envref run' 'execute run' 'ready run')")" "no_steps"

  if is_allowed_validator_action "upgrade_consumer_schema"; then
    run_case "A01" "validator_action_enum_known" "1" "1"
  else
    run_case "A01" "validator_action_enum_known" "0" "1"
  fi
  if is_allowed_validator_action "totally_unknown_action"; then
    run_case "A02" "validator_action_enum_unknown" "0" "1"
  else
    run_case "A02" "validator_action_enum_unknown" "1" "1"
  fi

  local tmp_jsonl out_force rc_force out_ok rc_ok out_ok_verify rc_ok_verify out_skip rc_skip out_bad_mode rc_bad_mode out_bad_mode_cli rc_bad_mode_cli out_bad_mode_cli_arg5 rc_bad_mode_cli_arg5 out_unexpected_extra rc_unexpected_extra out_unexpected_extra_multi rc_unexpected_extra_multi out_unexpected_extra_spaced rc_unexpected_extra_spaced out_unexpected_extra_preencoded rc_unexpected_extra_preencoded out_unexpected_extra_preencoded_plus rc_unexpected_extra_preencoded_plus out_unexpected_extra_raw_plus rc_unexpected_extra_raw_plus out_unexpected_extra_raw_percent rc_unexpected_extra_raw_percent out_unexpected_extra_raw_invalidpct rc_unexpected_extra_raw_invalidpct out_unexpected_extra_preencoded_percent rc_unexpected_extra_preencoded_percent out_unexpected_extra_preencoded_invalidpct rc_unexpected_extra_preencoded_invalidpct out_unexpected_extra_utf8_preencoded_invalidpct rc_unexpected_extra_utf8_preencoded_invalidpct out_unexpected_extra_utf8_preencoded_percent rc_unexpected_extra_utf8_preencoded_percent out_unexpected_extra_utf8_raw_percent rc_unexpected_extra_utf8_raw_percent out_unexpected_extra_utf8_raw_invalidpct rc_unexpected_extra_utf8_raw_invalidpct out_unexpected_extra_utf8_raw_plus rc_unexpected_extra_utf8_raw_plus out_unexpected_extra_utf8_raw_plus_percent rc_unexpected_extra_utf8_raw_plus_percent out_unexpected_extra_utf8_preencoded_plus_percent rc_unexpected_extra_utf8_preencoded_plus_percent out_unexpected_extra_utf8_preencoded_plus_invalidpct rc_unexpected_extra_utf8_preencoded_plus_invalidpct out_unexpected_extra_utf8_preencoded_plus_invalidpct_percent rc_unexpected_extra_utf8_preencoded_plus_invalidpct_percent out_unexpected_extra_utf8_preencoded_plus_invalidpct_deep rc_unexpected_extra_utf8_preencoded_plus_invalidpct_deep out_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper rc_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper out_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest rc_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest out_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme rc_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme out_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra rc_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra out_unexpected_extra_utf8_preencoded_plus_invalidpct_mega rc_unexpected_extra_utf8_preencoded_plus_invalidpct_mega out_unexpected_extra_utf8_preencoded_plus_invalidpct_giga rc_unexpected_extra_utf8_preencoded_plus_invalidpct_giga out_unexpected_extra_utf8_preencoded_plus_invalidpct_tera rc_unexpected_extra_utf8_preencoded_plus_invalidpct_tera out_unexpected_extra_utf8_preencoded_plus_invalidpct_peta rc_unexpected_extra_utf8_preencoded_plus_invalidpct_peta out_unexpected_extra_utf8_preencoded_plus_invalidpct_exa rc_unexpected_extra_utf8_preencoded_plus_invalidpct_exa out_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta rc_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta out_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta rc_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta out_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna rc_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna out_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta rc_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta out_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna rc_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna out_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra rc_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra out_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken rc_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken out_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan rc_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan out_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth rc_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth out_unexpected_extra_utf8_preencoded_plus_invalidpct_titan rc_unexpected_extra_utf8_preencoded_plus_invalidpct_titan out_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus rc_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus out_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas rc_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas out_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath rc_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath out_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops rc_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops out_unexpected_extra_utf8_preencoded_plus_invalidpct_ares rc_unexpected_extra_utf8_preencoded_plus_invalidpct_ares out_unexpected_extra_utf8_preencoded_plus_invalidpct_hera rc_unexpected_extra_utf8_preencoded_plus_invalidpct_hera out_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus rc_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus out_unexpected_extra_utf8_preencoded_plus_invalidpct_hades rc_unexpected_extra_utf8_preencoded_plus_invalidpct_hades out_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon rc_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon out_unexpected_extra_utf8_preencoded_plus_invalidpct_triton rc_unexpected_extra_utf8_preencoded_plus_invalidpct_triton out_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus rc_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus out_old_validator rc_old_validator out_missing_path rc_missing_path out_missing_file rc_missing_file out_missing_file_spaced rc_missing_file_spaced out_missing_file_special rc_missing_file_special out_missing_file_preencoded rc_missing_file_preencoded out_missing_file_mixed rc_missing_file_mixed out_missing_file_query rc_missing_file_query out_missing_file_punct rc_missing_file_punct out_missing_file_bracket rc_missing_file_bracket out_missing_file_quote rc_missing_file_quote out_missing_file_kv rc_missing_file_kv out_missing_file_invalidpct rc_missing_file_invalidpct out_missing_file_utf8 rc_missing_file_utf8 out_missing_file_utf8mix rc_missing_file_utf8mix missing_file_path missing_file_spaced_path missing_file_special_path missing_file_preencoded_path missing_file_mixed_path missing_file_query_path missing_file_punct_path missing_file_bracket_path missing_file_quote_path missing_file_kv_path missing_file_invalidpct_path missing_file_utf8_path missing_file_utf8mix_path expected_missing_file_spaced expected_missing_file_special expected_missing_file_preencoded expected_missing_file_mixed expected_missing_file_query expected_missing_file_punct expected_missing_file_bracket expected_missing_file_quote expected_missing_file_kv expected_missing_file_invalidpct expected_missing_file_utf8 expected_missing_file_utf8mix
  tmp_jsonl="$(mktemp /tmp/token-broker-selftest-XXXXXX.jsonl)"
  cat >"$tmp_jsonl" <<EOF
{"type":"summary","schema_version":"${SELFTEST_SCHEMA_VERSION}","compat_min_schema":"${SELFTEST_COMPAT_MIN_SCHEMA}","validator_version":"${VALIDATOR_VERSION}","compat_min_validator_version":"${VALIDATOR_COMPAT_MIN_VERSION}","pass":true}
EOF
  set +e
  out_force="$(VALIDATOR_FORCE_ACTION=totally_unknown_action validate_selftest_jsonl "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_force=$?
  out_ok="$(validate_selftest_jsonl "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_ok=$?
  out_ok_verify="$(validate_selftest_jsonl "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum 2>&1)"
  rc_ok_verify=$?
  out_skip="$(validate_selftest_jsonl "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --skip-checksum 2>&1)"
  rc_skip=$?
  out_bad_mode="$(validate_selftest_jsonl "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --checksum-mode=oops 2>&1)"
  rc_bad_mode=$?
  out_bad_mode_cli="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" --checksum-mode=oops 2>&1)"
  rc_bad_mode_cli=$?
  out_bad_mode_cli_arg5="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --checksum-mode=oops 2>&1)"
  rc_bad_mode_cli_arg5=$?
  out_unexpected_extra="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=1 2>&1)"
  rc_unexpected_extra=$?
  out_unexpected_extra_multi="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=1 --extra2=2 2>&1)"
  rc_unexpected_extra_multi=$?
  out_unexpected_extra_spaced="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum "--extra=hello world" --extra2=2 2>&1)"
  rc_unexpected_extra_spaced=$?
  out_unexpected_extra_preencoded="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=hello%20world --extra2=2 2>&1)"
  rc_unexpected_extra_preencoded=$?
  out_unexpected_extra_preencoded_plus="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=hello%2Bworld --extra2=2 2>&1)"
  rc_unexpected_extra_preencoded_plus=$?
  out_unexpected_extra_raw_plus="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=hello+world --extra2=2 2>&1)"
  rc_unexpected_extra_raw_plus=$?
  out_unexpected_extra_raw_percent="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=hello%world --extra2=2 2>&1)"
  rc_unexpected_extra_raw_percent=$?
  out_unexpected_extra_raw_invalidpct="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=hello%2world --extra2=2 2>&1)"
  rc_unexpected_extra_raw_invalidpct=$?
  out_unexpected_extra_preencoded_percent="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=hello%25world --extra2=2 2>&1)"
  rc_unexpected_extra_preencoded_percent=$?
  out_unexpected_extra_preencoded_invalidpct="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=hello%252world --extra2=2 2>&1)"
  rc_unexpected_extra_preencoded_invalidpct=$?
  out_unexpected_extra_utf8_preencoded_invalidpct="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_invalidpct=$?
  out_unexpected_extra_utf8_preencoded_percent="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%25片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_percent=$?
  out_unexpected_extra_utf8_raw_percent="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_raw_percent=$?
  out_unexpected_extra_utf8_raw_invalidpct="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_raw_invalidpct=$?
  out_unexpected_extra_utf8_raw_plus="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文+片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_raw_plus=$?
  out_unexpected_extra_utf8_raw_plus_percent="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文+%片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_raw_plus_percent=$?
  out_unexpected_extra_utf8_preencoded_plus_percent="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_percent=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_percent="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_percent=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_deep="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_deep=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_mega="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_mega=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_giga="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_giga=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_tera="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_tera=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_peta="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_peta=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_exa="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_exa=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_titan="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525252525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_titan=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252525252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525252525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525252525252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252525252525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_ares="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525252525252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_ares=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_hera="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525252525252525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_hera=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252525252525252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_hades="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525252525252525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_hades=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%252525252525252525252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_triton="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%2525252525252525252525252525252525片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_triton=$?
  out_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus="$(bash "${BASH_SOURCE[0]}" __self_test_json_validate__ "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" --verify-checksum --extra=中文%2B%25252525252525252525252525252525252片段 --extra2=2 2>&1)"
  rc_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus=$?
  out_old_validator="$(validate_selftest_jsonl "$tmp_jsonl" "$SELFTEST_SCHEMA_VERSION" token_broker_validator.v0 2>&1)"
  rc_old_validator=$?
  out_missing_path="$(validate_selftest_jsonl "" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_path=$?
  missing_file_path="/tmp/token-broker-selftest-missing-$$.jsonl"
  out_missing_file="$(validate_selftest_jsonl "$missing_file_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file=$?
  missing_file_spaced_path="/tmp/token broker selftest missing $$ file.jsonl"
  out_missing_file_spaced="$(validate_selftest_jsonl "$missing_file_spaced_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_spaced=$?
  expected_missing_file_spaced="${missing_file_spaced_path// /%20}"
  missing_file_special_path="/tmp/token broker %+? selftest missing $$ file.jsonl"
  out_missing_file_special="$(validate_selftest_jsonl "$missing_file_special_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_special=$?
  expected_missing_file_special="$(MISSING_FILE_SPECIAL_PATH="$missing_file_special_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_SPECIAL_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_preencoded_path="/tmp/token%20already encoded $$ file.jsonl"
  out_missing_file_preencoded="$(validate_selftest_jsonl "$missing_file_preencoded_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_preencoded=$?
  expected_missing_file_preencoded="$(MISSING_FILE_PREENCODED_PATH="$missing_file_preencoded_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_PREENCODED_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_mixed_path="/tmp/token%2Fsegment%3Avalue%20mix $$ file.jsonl"
  out_missing_file_mixed="$(validate_selftest_jsonl "$missing_file_mixed_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_mixed=$?
  expected_missing_file_mixed="$(MISSING_FILE_MIXED_PATH="$missing_file_mixed_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_MIXED_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_query_path="/tmp/token query #frag &and $$ file.jsonl"
  out_missing_file_query="$(validate_selftest_jsonl "$missing_file_query_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_query=$?
  expected_missing_file_query="$(MISSING_FILE_QUERY_PATH="$missing_file_query_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_QUERY_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_punct_path="/tmp/token;comma,boom! $$ file.jsonl"
  out_missing_file_punct="$(validate_selftest_jsonl "$missing_file_punct_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_punct=$?
  expected_missing_file_punct="$(MISSING_FILE_PUNCT_PATH="$missing_file_punct_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_PUNCT_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_bracket_path="/tmp/token(bracket)[set] $$ file.jsonl"
  out_missing_file_bracket="$(validate_selftest_jsonl "$missing_file_bracket_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_bracket=$?
  expected_missing_file_bracket="$(MISSING_FILE_BRACKET_PATH="$missing_file_bracket_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_BRACKET_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_quote_path="$(SELFTEST_PID="$$" python3 - <<'PY'
import os
print(f"/tmp/token\"dbl\"and'sng {os.environ['SELFTEST_PID']} file.jsonl")
PY
)"
  out_missing_file_quote="$(validate_selftest_jsonl "$missing_file_quote_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_quote=$?
  expected_missing_file_quote="$(MISSING_FILE_QUOTE_PATH="$missing_file_quote_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_QUOTE_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_kv_path="/tmp/token=user@domain $$ file.jsonl"
  out_missing_file_kv="$(validate_selftest_jsonl "$missing_file_kv_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_kv=$?
  expected_missing_file_kv="$(MISSING_FILE_KV_PATH="$missing_file_kv_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_KV_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_invalidpct_path="/tmp/token%ZZbad%2 $$ file.jsonl"
  out_missing_file_invalidpct="$(validate_selftest_jsonl "$missing_file_invalidpct_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_invalidpct=$?
  expected_missing_file_invalidpct="$(MISSING_FILE_INVALIDPCT_PATH="$missing_file_invalidpct_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_INVALIDPCT_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_utf8_path="/tmp/中文路徑 $$ 測試.jsonl"
  out_missing_file_utf8="$(validate_selftest_jsonl "$missing_file_utf8_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_utf8=$?
  expected_missing_file_utf8="$(MISSING_FILE_UTF8_PATH="$missing_file_utf8_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_UTF8_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  missing_file_utf8mix_path="/tmp/中文#片段&參數 $$ 測試.jsonl"
  out_missing_file_utf8mix="$(validate_selftest_jsonl "$missing_file_utf8mix_path" "$SELFTEST_SCHEMA_VERSION" "$VALIDATOR_VERSION" 2>&1)"
  rc_missing_file_utf8mix=$?
  expected_missing_file_utf8mix="$(MISSING_FILE_UTF8MIX_PATH="$missing_file_utf8mix_path" python3 - <<'PY'
import os
import urllib.parse
value = os.environ["MISSING_FILE_UTF8MIX_PATH"]
print(urllib.parse.quote(urllib.parse.unquote(value), safe='-._~:/=@'))
PY
)"
  set -e
  rm -f "$tmp_jsonl"
  if [[ "$rc_force" -ne 0 ]] && [[ "$out_force" == *"error_code=invalid_action_enum"* ]]; then
    run_case "A03" "validator_rejects_unknown_forced_action" "1" "1"
  else
    run_case "A03" "validator_rejects_unknown_forced_action" "0" "1"
  fi
  if [[ "$rc_ok" -eq 0 ]] && [[ "$out_ok" == *"validator_version=${VALIDATOR_VERSION}"* ]]; then
    run_case "A04" "validator_output_contains_version" "1" "1"
  else
    run_case "A04" "validator_output_contains_version" "0" "1"
  fi
  if [[ "$rc_old_validator" -ne 0 ]] && [[ "$out_old_validator" == *"error_code=validator_too_old"* ]]; then
    run_case "A05" "validator_version_compat_guard" "1" "1"
  else
    run_case "A05" "validator_version_compat_guard" "0" "1"
  fi

  if [[ "$rc_ok" -eq 0 ]] \
    && [[ "$out_ok" == *"result_code=validate_ok"* ]] \
    && [[ "$out_ok" == *"error_code=none"* ]] \
    && [[ "$out_ok" == *"action=none"* ]] \
    && [[ "$out_ok" == *"validator_version=${VALIDATOR_VERSION}"* ]] \
    && [[ "$out_ok" == *"consumer_validator_version=${VALIDATOR_VERSION}"* ]] \
    && [[ "$out_ok" == *"compat_min_validator_version=${VALIDATOR_COMPAT_MIN_VERSION}"* ]] \
    && [[ "$out_ok" == *"schema_version=${SELFTEST_SCHEMA_VERSION}"* ]] \
    && [[ "$out_ok" == *"compat_min_schema=${SELFTEST_COMPAT_MIN_SCHEMA}"* ]] \
    && [[ "$out_ok" == *"consumer_schema=${SELFTEST_SCHEMA_VERSION}"* ]] \
    && [[ "$out_ok" == *"cases="* ]] \
    && [[ "$out_ok" == *"checksum_verify_mode=verify"* ]] \
    && [[ "$out_ok" == *"checksum_algo=sha256-16"* ]] \
    && [[ "$out_ok" == *"checksum_scope_version=v1"* ]] \
    && [[ "$out_ok" == *"checksum_scope=result_code,error_code,action,validator_version,extras"* ]] \
    && [[ "$out_ok" == *"kv_checksum="* ]]; then
    run_case "A06" "validator_output_contains_all_required_fields" "1" "1"
  else
    run_case "A06" "validator_output_contains_all_required_fields" "0" "1"
  fi

  if [[ "$rc_old_validator" -ne 0 ]] \
    && [[ "$out_old_validator" == *"result_code=validate_failed"* ]] \
    && [[ "$out_old_validator" == *"error_code=validator_too_old"* ]] \
    && [[ "$out_old_validator" == *"action=upgrade_validator"* ]] \
    && [[ "$out_old_validator" == *"checksum_verify_mode=verify"* ]] \
    && [[ "$out_old_validator" == *"checksum_algo=sha256-16"* ]] \
    && [[ "$out_old_validator" == *"checksum_scope_version=v1"* ]] \
    && [[ "$out_old_validator" == *"checksum_scope=result_code,error_code,action,validator_version,extras"* ]] \
    && [[ "$out_old_validator" == *"kv_checksum="* ]] \
    && [[ "$rc_force" -ne 0 ]] \
    && [[ "$out_force" == *"result_code=validate_failed"* ]] \
    && [[ "$out_force" == *"error_code=invalid_action_enum"* ]] \
    && [[ "$out_force" == *"checksum_verify_mode=verify"* ]] \
    && [[ "$out_force" == *"checksum_algo=sha256-16"* ]] \
    && [[ "$out_force" == *"checksum_scope_version=v1"* ]] \
    && [[ "$out_force" == *"checksum_scope=result_code,error_code,action,validator_version,extras"* ]] \
    && [[ "$out_force" == *"kv_checksum="* ]]; then
    run_case "A07" "validator_fail_output_contains_required_fields" "1" "1"
  else
    run_case "A07" "validator_fail_output_contains_required_fields" "0" "1"
  fi

  if verify_validate_checksum_line "$out_ok"; then
    run_case "A08" "validator_ok_checksum_matches_scope" "1" "1"
  else
    run_case "A08" "validator_ok_checksum_matches_scope" "0" "1"
  fi

  if verify_validate_checksum_line "$out_old_validator" && verify_validate_checksum_line "$out_force"; then
    run_case "A09" "validator_fail_checksum_matches_scope" "1" "1"
  else
    run_case "A09" "validator_fail_checksum_matches_scope" "0" "1"
  fi

  local out_bad_scope_version
  out_bad_scope_version="${out_ok/checksum_scope_version=v1/checksum_scope_version=v999}"
  if ! verify_validate_checksum_line "$out_bad_scope_version"; then
    run_case "A10" "validator_rejects_unknown_checksum_scope_version" "1" "1"
  else
    run_case "A10" "validator_rejects_unknown_checksum_scope_version" "0" "1"
  fi

  if [[ "$rc_ok" -eq 0 ]] \
    && [[ "$out_ok" == *"checksum_verify_mode=verify"* ]] \
    && [[ "$rc_ok_verify" -eq 0 ]] \
    && [[ "$out_ok_verify" == *"checksum_verify_mode=verify"* ]]; then
    run_case "A11" "validator_checksum_verify_default_and_explicit_verify" "1" "1"
  else
    run_case "A11" "validator_checksum_verify_default_and_explicit_verify" "0" "1"
  fi

  if [[ "$rc_skip" -eq 0 ]] \
    && [[ "$out_skip" == *"checksum_verify_mode=skip"* ]] \
    && [[ "$out_ok" != *"checksum_verify_mode=skip"* ]] \
    && verify_validate_checksum_line "$out_skip"; then
    run_case "A12" "validator_checksum_skip_requires_explicit_flag" "1" "1"
  else
    run_case "A12" "validator_checksum_skip_requires_explicit_flag" "0" "1"
  fi

  if [[ "$rc_bad_mode" -ne 0 ]] && [[ "$out_bad_mode" == *"error_code=invalid_checksum_mode"* ]]; then
    run_case "A13" "validator_rejects_invalid_checksum_mode" "1" "1"
  else
    run_case "A13" "validator_rejects_invalid_checksum_mode" "0" "1"
  fi

  if [[ "$rc_bad_mode_cli" -eq 2 ]] \
    && [[ "$out_bad_mode_cli" == *"error_code=invalid_checksum_mode"* ]] \
    && [[ "$out_bad_mode_cli" == *"action=fix_cli_invocation"* ]] \
    && verify_validate_checksum_line "$out_bad_mode_cli"; then
    run_case "A18" "validator_cli_arg4_unknown_flag_maps_to_checksum_mode_error" "1" "1"
  else
    run_case "A18" "validator_cli_arg4_unknown_flag_maps_to_checksum_mode_error" "0" "1"
  fi

  if [[ "$rc_bad_mode_cli_arg5" -eq 2 ]] \
    && [[ "$out_bad_mode_cli_arg5" == *"error_code=invalid_checksum_mode"* ]] \
    && [[ "$out_bad_mode_cli_arg5" == *"action=fix_cli_invocation"* ]] \
    && verify_validate_checksum_line "$out_bad_mode_cli_arg5"; then
    run_case "A19" "validator_cli_arg5_unknown_flag_maps_to_checksum_mode_error" "1" "1"
  else
    run_case "A19" "validator_cli_arg5_unknown_flag_maps_to_checksum_mode_error" "0" "1"
  fi

  if [[ "$rc_unexpected_extra" -eq 2 ]] \
    && [[ "$out_unexpected_extra" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra" == *"action=fix_cli_invocation"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra"; then
    run_case "A20" "validator_cli_rejects_unexpected_extra_args" "1" "1"
  else
    run_case "A20" "validator_cli_rejects_unexpected_extra_args" "0" "1"
  fi

  if [[ "$rc_unexpected_extra" -eq 2 ]] \
    && [[ "$out_unexpected_extra" == *"extra_args_count=1"* ]] \
    && [[ "$out_unexpected_extra" == *"first_extra_arg=--extra=1"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra"; then
    run_case "A21" "validator_unexpected_extra_arg_values_are_correct" "1" "1"
  else
    run_case "A21" "validator_unexpected_extra_arg_values_are_correct" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_multi" -eq 2 ]] \
    && [[ "$out_unexpected_extra_multi" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_multi" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_multi" == *"first_extra_arg=--extra=1"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_multi"; then
    run_case "A22" "validator_unexpected_extra_args_multi_values_are_correct" "1" "1"
  else
    run_case "A22" "validator_unexpected_extra_args_multi_values_are_correct" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_spaced" -eq 2 ]] \
    && [[ "$out_unexpected_extra_spaced" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_spaced" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_spaced" == *"first_extra_arg=--extra=hello%20world"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_spaced"; then
    run_case "A23" "validator_unexpected_extra_arg_with_space_is_encoded" "1" "1"
  else
    run_case "A23" "validator_unexpected_extra_arg_with_space_is_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_preencoded" -eq 2 ]] \
    && [[ "$out_unexpected_extra_preencoded" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_preencoded" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_preencoded" == *"first_extra_arg=--extra=hello%20world"* ]] \
    && [[ "$out_unexpected_extra_preencoded" != *"%2520"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_preencoded"; then
    run_case "A36" "validator_unexpected_extra_arg_preencoded_not_double_encoded" "1" "1"
  else
    run_case "A36" "validator_unexpected_extra_arg_preencoded_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_preencoded_plus" -eq 2 ]] \
    && [[ "$out_unexpected_extra_preencoded_plus" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_preencoded_plus" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_preencoded_plus" == *"first_extra_arg=--extra=hello%2Bworld"* ]] \
    && [[ "$out_unexpected_extra_preencoded_plus" != *"%252B"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_preencoded_plus"; then
    run_case "A37" "validator_unexpected_extra_arg_preencoded_plus_not_double_encoded" "1" "1"
  else
    run_case "A37" "validator_unexpected_extra_arg_preencoded_plus_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_raw_plus" -eq 2 ]] \
    && [[ "$out_unexpected_extra_raw_plus" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_raw_plus" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_raw_plus" == *"first_extra_arg=--extra=hello%2Bworld"* ]] \
    && [[ "$out_unexpected_extra_raw_plus" != *"first_extra_arg=--extra=hello+world"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_raw_plus"; then
    run_case "A38" "validator_unexpected_extra_arg_raw_plus_is_canonicalized" "1" "1"
  else
    run_case "A38" "validator_unexpected_extra_arg_raw_plus_is_canonicalized" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_raw_percent" -eq 2 ]] \
    && [[ "$out_unexpected_extra_raw_percent" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_raw_percent" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_raw_percent" == *"first_extra_arg=--extra=hello%25world"* ]] \
    && [[ "$out_unexpected_extra_raw_percent" != *"first_extra_arg=--extra=hello%world"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_raw_percent"; then
    run_case "A39" "validator_unexpected_extra_arg_raw_percent_is_canonicalized" "1" "1"
  else
    run_case "A39" "validator_unexpected_extra_arg_raw_percent_is_canonicalized" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_raw_invalidpct" -eq 2 ]] \
    && [[ "$out_unexpected_extra_raw_invalidpct" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_raw_invalidpct" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_raw_invalidpct" == *"first_extra_arg=--extra=hello%252world"* ]] \
    && [[ "$out_unexpected_extra_raw_invalidpct" != *"first_extra_arg=--extra=hello%2world"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_raw_invalidpct"; then
    run_case "A40" "validator_unexpected_extra_arg_raw_invalid_percent_is_canonicalized" "1" "1"
  else
    run_case "A40" "validator_unexpected_extra_arg_raw_invalid_percent_is_canonicalized" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_preencoded_percent" -eq 2 ]] \
    && [[ "$out_unexpected_extra_preencoded_percent" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_preencoded_percent" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_preencoded_percent" == *"first_extra_arg=--extra=hello%25world"* ]] \
    && [[ "$out_unexpected_extra_preencoded_percent" != *"%2525world"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_preencoded_percent"; then
    run_case "A41" "validator_unexpected_extra_arg_preencoded_percent_not_double_encoded" "1" "1"
  else
    run_case "A41" "validator_unexpected_extra_arg_preencoded_percent_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_preencoded_invalidpct" -eq 2 ]] \
    && [[ "$out_unexpected_extra_preencoded_invalidpct" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_preencoded_invalidpct" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_preencoded_invalidpct" == *"first_extra_arg=--extra=hello%252world"* ]] \
    && [[ "$out_unexpected_extra_preencoded_invalidpct" != *"%25252world"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_preencoded_invalidpct"; then
    run_case "A42" "validator_unexpected_extra_arg_preencoded_invalid_percent_not_double_encoded" "1" "1"
  else
    run_case "A42" "validator_unexpected_extra_arg_preencoded_invalid_percent_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_invalidpct" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_invalidpct" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_invalidpct" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_invalidpct" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_invalidpct" != *"%25252%E7%89%87%E6%AE%B5"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_invalidpct"; then
    run_case "A43" "validator_unexpected_extra_arg_utf8_preencoded_invalid_percent_not_double_encoded" "1" "1"
  else
    run_case "A43" "validator_unexpected_extra_arg_utf8_preencoded_invalid_percent_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_percent" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_percent" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_percent" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_percent" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%25%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_percent" != *"%2525%E7%89%87%E6%AE%B5"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_percent"; then
    run_case "A44" "validator_unexpected_extra_arg_utf8_preencoded_percent_not_double_encoded" "1" "1"
  else
    run_case "A44" "validator_unexpected_extra_arg_utf8_preencoded_percent_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_raw_percent" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_raw_percent" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_percent" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_percent" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%25%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_percent" != *"first_extra_arg=--extra=中文%片段"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_raw_percent"; then
    run_case "A45" "validator_unexpected_extra_arg_utf8_raw_percent_is_canonicalized" "1" "1"
  else
    run_case "A45" "validator_unexpected_extra_arg_utf8_raw_percent_is_canonicalized" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_raw_invalidpct" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_raw_invalidpct" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_invalidpct" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_invalidpct" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_invalidpct" != *"first_extra_arg=--extra=中文%2片段"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_raw_invalidpct"; then
    run_case "A46" "validator_unexpected_extra_arg_utf8_raw_invalid_percent_is_canonicalized" "1" "1"
  else
    run_case "A46" "validator_unexpected_extra_arg_utf8_raw_invalid_percent_is_canonicalized" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_raw_plus" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_raw_plus" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_plus" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_plus" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_plus" != *"first_extra_arg=--extra=中文+片段"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_raw_plus"; then
    run_case "A47" "validator_unexpected_extra_arg_utf8_raw_plus_is_canonicalized" "1" "1"
  else
    run_case "A47" "validator_unexpected_extra_arg_utf8_raw_plus_is_canonicalized" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_raw_plus_percent" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_raw_plus_percent" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_plus_percent" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_plus_percent" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_raw_plus_percent" != *"first_extra_arg=--extra=中文+%片段"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_raw_plus_percent"; then
    run_case "A48" "validator_unexpected_extra_arg_utf8_raw_plus_percent_is_canonicalized" "1" "1"
  else
    run_case "A48" "validator_unexpected_extra_arg_utf8_raw_plus_percent_is_canonicalized" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_percent" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_percent" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_percent" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_percent" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_percent" != *"%252B%2525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_percent"; then
    run_case "A49" "validator_unexpected_extra_arg_utf8_preencoded_plus_percent_not_double_encoded" "1" "1"
  else
    run_case "A49" "validator_unexpected_extra_arg_utf8_preencoded_plus_percent_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct" != *"%252B%25252"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct"; then
    run_case "A50" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalid_percent_not_double_encoded" "1" "1"
  else
    run_case "A50" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalid_percent_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_percent" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_percent" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_percent" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_percent" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_percent" != *"%252B%252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_percent"; then
    run_case "A51" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_percent_not_double_encoded" "1" "1"
  else
    run_case "A51" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_percent_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_deep" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deep" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deep" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deep" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deep" != *"%252B%2525252"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deep"; then
    run_case "A52" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_deep_not_double_encoded" "1" "1"
  else
    run_case "A52" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_deep_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper" != *"%252B%25252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deeper"; then
    run_case "A53" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_deeper_not_double_encoded" "1" "1"
  else
    run_case "A53" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_deeper_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest" != *"%252B%252525252"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_deepest"; then
    run_case "A54" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_deepest_not_double_encoded" "1" "1"
  else
    run_case "A54" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_deepest_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme" != *"%252B%2525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_extreme"; then
    run_case "A55" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_extreme_not_double_encoded" "1" "1"
  else
    run_case "A55" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_extreme_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra" != *"%252B%25252525252"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ultra"; then
    run_case "A56" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_ultra_not_double_encoded" "1" "1"
  else
    run_case "A56" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_ultra_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_mega" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_mega" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_mega" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_mega" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_mega" != *"%252B%252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_mega"; then
    run_case "A57" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_mega_not_double_encoded" "1" "1"
  else
    run_case "A57" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_mega_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_giga" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_giga" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_giga" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_giga" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_giga" != *"%252B%2525252525252"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_giga"; then
    run_case "A58" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_giga_not_double_encoded" "1" "1"
  else
    run_case "A58" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_giga_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_tera" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_tera" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_tera" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_tera" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_tera" != *"%252B%25252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_tera"; then
    run_case "A59" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_tera_not_double_encoded" "1" "1"
  else
    run_case "A59" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_tera_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_peta" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_peta" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_peta" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_peta" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_peta" != *"%252B%25252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_peta"; then
    run_case "A60" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_peta_not_double_encoded" "1" "1"
  else
    run_case "A60" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_peta_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_exa" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_exa" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_exa" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_exa" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_exa" != *"%252B%2525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_exa"; then
    run_case "A61" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_exa_not_double_encoded" "1" "1"
  else
    run_case "A61" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_exa_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta" != *"%252B%25252525252525252"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_yotta"; then
    run_case "A62" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_yotta_not_double_encoded" "1" "1"
  else
    run_case "A62" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_yotta_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta" != *"%252B%252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zetta"; then
    run_case "A63" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_zetta_not_double_encoded" "1" "1"
  else
    run_case "A63" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_zetta_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna" != *"%252B%252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ronna"; then
    run_case "A64" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_ronna_not_double_encoded" "1" "1"
  else
    run_case "A64" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_ronna_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta" != *"%252B%25252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_quetta"; then
    run_case "A65" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_quetta_not_double_encoded" "1" "1"
  else
    run_case "A65" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_quetta_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna" != *"%252B%25252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_xonna"; then
    run_case "A66" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_xonna_not_double_encoded" "1" "1"
  else
    run_case "A66" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_xonna_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra" != *"%252B%2525252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hydra"; then
    run_case "A67" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_hydra_not_double_encoded" "1" "1"
  else
    run_case "A67" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_hydra_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken" != *"%252B%2525252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_kraken"; then
    run_case "A68" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_kraken_not_double_encoded" "1" "1"
  else
    run_case "A68" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_kraken_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan" != *"%252B%252525252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_leviathan"; then
    run_case "A69" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_leviathan_not_double_encoded" "1" "1"
  else
    run_case "A69" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_leviathan_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth" != *"%252B%252525252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_behemoth"; then
    run_case "A70" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_behemoth_not_double_encoded" "1" "1"
  else
    run_case "A70" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_behemoth_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_titan" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_titan" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_titan" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_titan" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525252525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_titan" != *"%252B%25252525252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_titan"; then
    run_case "A71" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_titan_not_double_encoded" "1" "1"
  else
    run_case "A71" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_titan_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252525252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus" != *"%252B%25252525252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_colossus"; then
    run_case "A72" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_colossus_not_double_encoded" "1" "1"
  else
    run_case "A72" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_colossus_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525252525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas" != *"%252B%2525252525252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_atlas"; then
    run_case "A73" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_atlas_not_double_encoded" "1" "1"
  else
    run_case "A73" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_atlas_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525252525252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath" != *"%252B%2525252525252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_goliath"; then
    run_case "A74" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_goliath_not_double_encoded" "1" "1"
  else
    run_case "A74" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_goliath_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252525252525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops" != *"%252B%252525252525252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_cyclops"; then
    run_case "A75" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_cyclops_not_double_encoded" "1" "1"
  else
    run_case "A75" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_cyclops_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_ares" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ares" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ares" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ares" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525252525252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ares" != *"%252B%252525252525252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_ares"; then
    run_case "A76" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_ares_not_double_encoded" "1" "1"
  else
    run_case "A76" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_ares_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_hera" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hera" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hera" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hera" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525252525252525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hera" != *"%252B%25252525252525252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hera"; then
    run_case "A77" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_hera_not_double_encoded" "1" "1"
  else
    run_case "A77" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_hera_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252525252525252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus" != *"%252B%25252525252525252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_zeus"; then
    run_case "A78" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_zeus_not_double_encoded" "1" "1"
  else
    run_case "A78" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_zeus_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_hades" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hades" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hades" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hades" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525252525252525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hades" != *"%252B%2525252525252525252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_hades"; then
    run_case "A79" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_hades_not_double_encoded" "1" "1"
  else
    run_case "A79" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_hades_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%252525252525252525252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon" != *"%252B%2525252525252525252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_poseidon"; then
    run_case "A80" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_poseidon_not_double_encoded" "1" "1"
  else
    run_case "A80" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_poseidon_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_triton" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_triton" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_triton" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_triton" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%2525252525252525252525252525252525%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_triton" != *"%252B%252525252525252525252525252525252525"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_triton"; then
    run_case "A81" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_triton_not_double_encoded" "1" "1"
  else
    run_case "A81" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_triton_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus" -eq 2 ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus" == *"error_code=unexpected_extra_args"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus" == *"extra_args_count=2"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus" == *"first_extra_arg=--extra=%E4%B8%AD%E6%96%87%2B%25252525252525252525252525252525252%E7%89%87%E6%AE%B5"* ]] \
    && [[ "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus" != *"%252B%252525252525252525252525252525252522"* ]] \
    && verify_validate_checksum_line "$out_unexpected_extra_utf8_preencoded_plus_invalidpct_proteus"; then
    run_case "A82" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_proteus_not_double_encoded" "1" "1"
  else
    run_case "A82" "validator_unexpected_extra_arg_utf8_preencoded_plus_invalidpct_proteus_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_bad_mode" -ne 0 ]] \
    && [[ "$out_bad_mode" == *"action=fix_cli_invocation"* ]] \
    && [[ "$out_bad_mode" == *"checksum_verify_mode=verify"* ]] \
    && [[ "$out_bad_mode" == *"checksum_algo=sha256-16"* ]] \
    && verify_validate_checksum_line "$out_bad_mode"; then
    run_case "A14" "validator_invalid_checksum_mode_has_stable_machine_fields" "1" "1"
  else
    run_case "A14" "validator_invalid_checksum_mode_has_stable_machine_fields" "0" "1"
  fi

  local out_checksum_verify_failed
  out_checksum_verify_failed="$(emit_validator_fail_line checksum_verify_failed verify validator_output_corrupted=1)"
  if [[ "$out_checksum_verify_failed" == *"error_code=checksum_verify_failed"* ]] \
    && [[ "$out_checksum_verify_failed" == *"action=inspect_validator_output"* ]] \
    && [[ "$out_checksum_verify_failed" == *"checksum_verify_mode=verify"* ]] \
    && verify_validate_checksum_line "$out_checksum_verify_failed"; then
    run_case "A15" "validator_checksum_verify_failed_has_stable_machine_fields" "1" "1"
  else
    run_case "A15" "validator_checksum_verify_failed_has_stable_machine_fields" "0" "1"
  fi

  if [[ "$rc_missing_path" -eq 2 ]] \
    && [[ "$out_missing_path" == *"error_code=missing_file_path"* ]] \
    && [[ "$out_missing_path" == *"action=fix_cli_invocation"* ]] \
    && [[ "$out_missing_path" == *"checksum_verify_mode=verify"* ]] \
    && verify_validate_checksum_line "$out_missing_path"; then
    run_case "A16" "validator_missing_file_path_has_stable_machine_fields" "1" "1"
  else
    run_case "A16" "validator_missing_file_path_has_stable_machine_fields" "0" "1"
  fi

  if [[ "$rc_missing_file" -eq 2 ]] \
    && [[ "$out_missing_file" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file" == *"action=provide_valid_jsonl_path"* ]] \
    && [[ "$out_missing_file" == *"path=${missing_file_path}"* ]] \
    && [[ "$out_missing_file" == *"checksum_verify_mode=verify"* ]] \
    && verify_validate_checksum_line "$out_missing_file"; then
    run_case "A17" "validator_file_not_found_has_stable_machine_fields" "1" "1"
  else
    run_case "A17" "validator_file_not_found_has_stable_machine_fields" "0" "1"
  fi

  if [[ "$rc_missing_file_spaced" -eq 2 ]] \
    && [[ "$out_missing_file_spaced" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_spaced" == *"action=provide_valid_jsonl_path"* ]] \
    && [[ "$out_missing_file_spaced" == *"path=${expected_missing_file_spaced}"* ]] \
    && [[ "$out_missing_file_spaced" == *"checksum_verify_mode=verify"* ]] \
    && verify_validate_checksum_line "$out_missing_file_spaced"; then
    run_case "A24" "validator_file_not_found_spaced_path_is_encoded" "1" "1"
  else
    run_case "A24" "validator_file_not_found_spaced_path_is_encoded" "0" "1"
  fi

  if [[ "$rc_missing_file_special" -eq 2 ]] \
    && [[ "$out_missing_file_special" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_special" == *"action=provide_valid_jsonl_path"* ]] \
    && [[ "$out_missing_file_special" == *"path=${expected_missing_file_special}"* ]] \
    && [[ "$out_missing_file_special" == *"checksum_verify_mode=verify"* ]] \
    && verify_validate_checksum_line "$out_missing_file_special"; then
    run_case "A25" "validator_file_not_found_special_path_is_encoded" "1" "1"
  else
    run_case "A25" "validator_file_not_found_special_path_is_encoded" "0" "1"
  fi

  if [[ "$rc_missing_file_preencoded" -eq 2 ]] \
    && [[ "$out_missing_file_preencoded" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_preencoded" == *"path=${expected_missing_file_preencoded}"* ]] \
    && [[ "$out_missing_file_preencoded" != *"%2520"* ]] \
    && verify_validate_checksum_line "$out_missing_file_preencoded"; then
    run_case "A26" "validator_file_not_found_preencoded_path_not_double_encoded" "1" "1"
  else
    run_case "A26" "validator_file_not_found_preencoded_path_not_double_encoded" "0" "1"
  fi

  if [[ "$rc_missing_file_mixed" -eq 2 ]] \
    && [[ "$out_missing_file_mixed" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_mixed" == *"path=${expected_missing_file_mixed}"* ]] \
    && [[ "$out_missing_file_mixed" != *"%252F"* ]] \
    && [[ "$out_missing_file_mixed" != *"%253A"* ]] \
    && verify_validate_checksum_line "$out_missing_file_mixed"; then
    run_case "A27" "validator_file_not_found_mixed_encoded_path_is_canonical" "1" "1"
  else
    run_case "A27" "validator_file_not_found_mixed_encoded_path_is_canonical" "0" "1"
  fi

  if [[ "$rc_missing_file_query" -eq 2 ]] \
    && [[ "$out_missing_file_query" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_query" == *"path=${expected_missing_file_query}"* ]] \
    && [[ "$out_missing_file_query" == *"%23"* ]] \
    && [[ "$out_missing_file_query" == *"%26"* ]] \
    && verify_validate_checksum_line "$out_missing_file_query"; then
    run_case "A28" "validator_file_not_found_query_chars_are_encoded" "1" "1"
  else
    run_case "A28" "validator_file_not_found_query_chars_are_encoded" "0" "1"
  fi

  if [[ "$rc_missing_file_punct" -eq 2 ]] \
    && [[ "$out_missing_file_punct" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_punct" == *"path=${expected_missing_file_punct}"* ]] \
    && [[ "$out_missing_file_punct" == *"%3B"* ]] \
    && [[ "$out_missing_file_punct" == *"%2C"* ]] \
    && [[ "$out_missing_file_punct" == *"%21"* ]] \
    && verify_validate_checksum_line "$out_missing_file_punct"; then
    run_case "A29" "validator_file_not_found_punctuation_chars_are_encoded" "1" "1"
  else
    run_case "A29" "validator_file_not_found_punctuation_chars_are_encoded" "0" "1"
  fi

  if [[ "$rc_missing_file_bracket" -eq 2 ]] \
    && [[ "$out_missing_file_bracket" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_bracket" == *"path=${expected_missing_file_bracket}"* ]] \
    && [[ "$out_missing_file_bracket" == *"%28"* ]] \
    && [[ "$out_missing_file_bracket" == *"%29"* ]] \
    && [[ "$out_missing_file_bracket" == *"%5B"* ]] \
    && [[ "$out_missing_file_bracket" == *"%5D"* ]] \
    && verify_validate_checksum_line "$out_missing_file_bracket"; then
    run_case "A30" "validator_file_not_found_bracket_chars_are_encoded" "1" "1"
  else
    run_case "A30" "validator_file_not_found_bracket_chars_are_encoded" "0" "1"
  fi

  if [[ "$rc_missing_file_quote" -eq 2 ]] \
    && [[ "$out_missing_file_quote" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_quote" == *"path=${expected_missing_file_quote}"* ]] \
    && [[ "$out_missing_file_quote" == *"%22"* ]] \
    && [[ "$out_missing_file_quote" == *"%27"* ]] \
    && verify_validate_checksum_line "$out_missing_file_quote"; then
    run_case "A31" "validator_file_not_found_quote_chars_are_encoded" "1" "1"
  else
    run_case "A31" "validator_file_not_found_quote_chars_are_encoded" "0" "1"
  fi

  if [[ "$rc_missing_file_kv" -eq 2 ]] \
    && [[ "$out_missing_file_kv" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_kv" == *"path=${expected_missing_file_kv}"* ]] \
    && [[ "$out_missing_file_kv" == *"token=user@domain"* ]] \
    && verify_validate_checksum_line "$out_missing_file_kv"; then
    run_case "A32" "validator_file_not_found_kv_chars_are_preserved" "1" "1"
  else
    run_case "A32" "validator_file_not_found_kv_chars_are_preserved" "0" "1"
  fi

  if [[ "$rc_missing_file_invalidpct" -eq 2 ]] \
    && [[ "$out_missing_file_invalidpct" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_invalidpct" == *"path=${expected_missing_file_invalidpct}"* ]] \
    && [[ "$out_missing_file_invalidpct" == *"%25ZZ"* ]] \
    && [[ "$out_missing_file_invalidpct" == *"%252"* ]] \
    && verify_validate_checksum_line "$out_missing_file_invalidpct"; then
    run_case "A33" "validator_file_not_found_invalid_percent_sequences_are_canonicalized" "1" "1"
  else
    run_case "A33" "validator_file_not_found_invalid_percent_sequences_are_canonicalized" "0" "1"
  fi

  if [[ "$rc_missing_file_utf8" -eq 2 ]] \
    && [[ "$out_missing_file_utf8" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_utf8" == *"path=${expected_missing_file_utf8}"* ]] \
    && [[ "$out_missing_file_utf8" == *"%E4%B8%AD%E6%96%87"* ]] \
    && verify_validate_checksum_line "$out_missing_file_utf8"; then
    run_case "A34" "validator_file_not_found_utf8_path_is_encoded" "1" "1"
  else
    run_case "A34" "validator_file_not_found_utf8_path_is_encoded" "0" "1"
  fi

  if [[ "$rc_missing_file_utf8mix" -eq 2 ]] \
    && [[ "$out_missing_file_utf8mix" == *"error_code=file_not_found"* ]] \
    && [[ "$out_missing_file_utf8mix" == *"path=${expected_missing_file_utf8mix}"* ]] \
    && [[ "$out_missing_file_utf8mix" == *"%E4%B8%AD%E6%96%87"* ]] \
    && [[ "$out_missing_file_utf8mix" == *"%23"* ]] \
    && [[ "$out_missing_file_utf8mix" == *"%26"* ]] \
    && verify_validate_checksum_line "$out_missing_file_utf8mix"; then
    run_case "A35" "validator_file_not_found_utf8_mixed_reserved_chars_are_encoded" "1" "1"
  else
    run_case "A35" "validator_file_not_found_utf8_mixed_reserved_chars_are_encoded" "0" "1"
  fi

  emit_self_test_summary "$format" "$total" "$failed"
  [[ "$failed" -eq 0 ]]
}

validate_selftest_jsonl() {
  local file_path="$1"
  local consumer_schema="${2:-$SELFTEST_SCHEMA_VERSION}"
  local consumer_validator_version="${3:-$VALIDATOR_VERSION}"
  local checksum_mode_arg="${4:---verify-checksum}"
  local checksum_verify_mode="verify"

  case "$checksum_mode_arg" in
    ""|verify|--verify-checksum)
      checksum_verify_mode="verify"
      ;;
    skip|--skip-checksum)
      checksum_verify_mode="skip"
      ;;
    *)
      emit_validator_fail_line "invalid_checksum_mode" "$checksum_verify_mode" "checksum_mode=${checksum_mode_arg}"
      return 2
      ;;
  esac

  if [[ -z "$file_path" ]]; then
    emit_validator_fail_line "missing_file_path" "$checksum_verify_mode"
    return 2
  fi
  if [[ ! -f "$file_path" ]]; then
    emit_validator_fail_line "file_not_found" "$checksum_verify_mode" "path=$file_path"
    return 2
  fi

  local out rc
  set +e
  out="$(SELFTEST_FILE="$file_path" CONSUMER_SCHEMA="$consumer_schema" CONSUMER_VALIDATOR_VERSION="$consumer_validator_version" VALIDATOR_VERSION="$VALIDATOR_VERSION" CHECKSUM_VERIFY_MODE="$checksum_verify_mode" python3 - <<'PY'
import hashlib
import json
import os
import re
import sys
from pathlib import Path

path = Path(os.environ["SELFTEST_FILE"])
consumer_schema = os.environ.get("CONSUMER_SCHEMA", "")
consumer_validator_version = os.environ.get("CONSUMER_VALIDATOR_VERSION", "")
validator_version = os.environ.get("VALIDATOR_VERSION", "")
forced_action = os.environ.get("VALIDATOR_FORCE_ACTION", "").strip()
checksum_verify_mode = os.environ.get("CHECKSUM_VERIFY_MODE", "verify").strip() or "verify"
if checksum_verify_mode not in {"verify", "skip"}:
    checksum_verify_mode = "verify"


def major(schema: str) -> int:
    m = re.search(r"\.v(\d+)$", schema or "")
    return int(m.group(1)) if m else -1


ALLOWED_ACTIONS = {
    "none",
    "fix_cli_invocation",
    "provide_valid_jsonl_path",
    "regenerate_selftest_jsonl",
    "upgrade_consumer_schema",
    "upgrade_validator",
    "investigate_selftest_failures",
    "inspect_validator_output",
}


CHECKSUM_ALGO = "sha256-16"
CHECKSUM_SCOPE_VERSION = "v1"
CHECKSUM_SCOPE_BY_VERSION = {
    "v1": "result_code,error_code,action,validator_version,extras",
}
CHECKSUM_SCOPE = CHECKSUM_SCOPE_BY_VERSION[CHECKSUM_SCOPE_VERSION]


def checksum_for_kv(kv_parts):
    payload = "|".join(kv_parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def emit_validate_line(kind: str, result_code: str, error_code: str, action: str, extra_parts):
    checksum_parts = [
        f"result_code={result_code}",
        f"error_code={error_code}",
        f"action={action}",
        f"validator_version={validator_version}",
        f"checksum_verify_mode={checksum_verify_mode}",
    ]
    checksum_parts.extend(extra_parts)
    checksum = checksum_for_kv(checksum_parts)

    kv_parts = list(checksum_parts)
    kv_parts.append(f"checksum_algo={CHECKSUM_ALGO}")
    kv_parts.append(f"checksum_scope_version={CHECKSUM_SCOPE_VERSION}")
    kv_parts.append(f"checksum_scope={CHECKSUM_SCOPE}")
    kv_parts.append(f"kv_checksum={checksum}")
    print(" ".join([kind] + kv_parts))


def fail_invalid_action(action_value: str, code: str):
    emit_validate_line(
        "SELF_TEST_JSON_VALIDATE_FAIL",
        "validate_failed",
        "invalid_action_enum",
        "inspect_validator_output",
        [f"action_value={action_value}", f"for_error_code={code}"],
    )
    sys.exit(1)


def ensure_allowed(action: str, code: str) -> str:
    if action not in ALLOWED_ACTIONS:
        fail_invalid_action(action, code)
    return action


def action_for_error(code: str) -> str:
    mapping = {
        "missing_file_path": "fix_cli_invocation",
        "file_not_found": "provide_valid_jsonl_path",
        "empty_jsonl": "regenerate_selftest_jsonl",
        "invalid_json": "regenerate_selftest_jsonl",
        "missing_summary": "regenerate_selftest_jsonl",
        "schema_too_old": "upgrade_consumer_schema",
        "validator_too_old": "upgrade_validator",
        "summary_pass_false": "investigate_selftest_failures",
        "invalid_action_enum": "inspect_validator_output",
        "invalid_checksum_mode": "fix_cli_invocation",
        "unexpected_extra_args": "fix_cli_invocation",
        "checksum_verify_failed": "inspect_validator_output",
    }
    base = mapping.get(code, "inspect_validator_output")
    chosen = forced_action or base
    return ensure_allowed(chosen, code)


def action_for_success() -> str:
    chosen = forced_action or "none"
    return ensure_allowed(chosen, "none")


def fail(code: str, *extra: str):
    emit_validate_line(
        "SELF_TEST_JSON_VALIDATE_FAIL",
        "validate_failed",
        code,
        action_for_error(code),
        list(extra),
    )
    sys.exit(1)


lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
if not lines:
    fail("empty_jsonl")

objs = []
for i, ln in enumerate(lines, 1):
    try:
        objs.append(json.loads(ln))
    except Exception as e:
        fail("invalid_json", f"line={i}", f"err={e}")

summary = next((o for o in objs if o.get("type") == "summary"), None)
if not summary:
    fail("missing_summary")

schema_version = summary.get("schema_version", "")
compat_min = summary.get("compat_min_schema", schema_version)
summary_validator_version = summary.get("validator_version", validator_version)
compat_min_validator = summary.get("compat_min_validator_version", summary_validator_version)

if major(consumer_schema) < major(compat_min):
    fail("schema_too_old", f"consumer_schema={consumer_schema}", f"compat_min_schema={compat_min}")

if major(consumer_validator_version) < major(compat_min_validator):
    fail(
        "validator_too_old",
        f"consumer_validator_version={consumer_validator_version}",
        f"compat_min_validator_version={compat_min_validator}",
    )

if not summary.get("pass", False):
    fail("summary_pass_false")

emit_validate_line(
    "SELF_TEST_JSON_VALIDATE_OK",
    "validate_ok",
    "none",
    action_for_success(),
    [
        f"consumer_validator_version={consumer_validator_version}",
        f"compat_min_validator_version={compat_min_validator}",
        f"schema_version={schema_version}",
        f"compat_min_schema={compat_min}",
        f"consumer_schema={consumer_schema}",
        f"cases={len([o for o in objs if o.get('type') == 'case'])}",
    ],
)
PY
)"
  rc=$?
  set -e

  if [[ "$rc" -ne 0 ]]; then
    echo "$out"
    return "$rc"
  fi

  if [[ "$checksum_verify_mode" == "verify" ]]; then
    if ! verify_validate_checksum_line "$out"; then
      echo "$out"
      emit_validator_fail_line "checksum_verify_failed" "$checksum_verify_mode" "validator_output_corrupted=1"
      return 1
    fi
  fi

  echo "$out"
}

get_container_ip() {
  lxc list "$CONTAINER" -c 4 --format csv | awk 'NR==1{print $1}'
}

sanitize_tag() {
  sed 's/[^[:alnum:]_]/_/g' <<<"$1"
}

nft_chain_dump() {
  sudo -n nft --handle list chain ip cella_tproxy prerouting 2>/dev/null || true
}

remove_nft_tag_rules() {
  local tag="$1"
  local handles
  handles="$(nft_chain_dump | awk -v t="$tag" 'index($0,t)>0 { split($0,a,"# handle "); if (a[2]!="") print a[2] }')"
  if [[ -z "$handles" ]]; then
    return 0
  fi
  while IFS= read -r h; do
    [[ -z "$h" ]] && continue
    sudo -n nft delete rule ip cella_tproxy prerouting handle "$h" >/dev/null 2>&1 || true
  done <<<"$handles"
}

listener_pid_for_port() {
  sudo -n ss -ltnp 2>/dev/null \
    | awk -v p=":${PORT}" '$0 ~ p { if (match($0,/pid=[0-9]+/)) { print substr($0,RSTART+4,RLENGTH-4); exit } }'
}

pid_cmdline() {
  local pid="$1"
  sudo -n tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null || true
}

reclaim_proxy_port_if_needed() {
  local pid cmd
  pid="$(listener_pid_for_port || true)"
  if [[ -z "$pid" ]]; then
    return 0
  fi

  cmd="$(pid_cmdline "$pid")"
  if [[ "$PREEMPT_PORT" == "1" ]] && [[ "$cmd" == *" cmd proxy "* || "$cmd" == *"/exe/cmd proxy "* || "$cmd" == *"cella-proxy-e2e-bin proxy "* ]]; then
    echo "[preflight] port $PORT occupied by stale proxy pid=$pid; sending SIGINT"
    sudo -n kill -INT "$pid" 2>/dev/null || true
    sleep 1
    if sudo -n kill -0 "$pid" 2>/dev/null; then
      sudo -n kill -TERM "$pid" 2>/dev/null || true
      sleep 1
    fi
  fi

  pid="$(listener_pid_for_port || true)"
  if [[ -n "$pid" ]]; then
    cmd="$(pid_cmdline "$pid")"
    echo "[error] port $PORT still occupied by pid=$pid"
    echo "[error] cmdline: $cmd"
    exit 9
  fi
}

graceful_stop_proxy() {
  if [[ "$proxy_stopped" -eq 1 ]]; then
    return 0
  fi
  if [[ -z "$proxy_pid" ]] || ! kill -0 "$proxy_pid" 2>/dev/null; then
    proxy_stopped=1
    return 0
  fi

  kill -INT "$proxy_pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    if ! kill -0 "$proxy_pid" 2>/dev/null; then
      wait "$proxy_pid" 2>/dev/null || true
      proxy_stopped=1
      return 0
    fi
    sleep 0.2
  done

  kill -TERM "$proxy_pid" 2>/dev/null || true
  wait "$proxy_pid" 2>/dev/null || true
  proxy_stopped=1
}

cleanup() {
  graceful_stop_proxy
}
trap cleanup EXIT INT TERM

if [[ "${1:-}" == "__self_test__" ]]; then
  run_self_tests text
  exit $?
fi
if [[ "${1:-}" == "__self_test_json__" ]]; then
  run_self_tests json
  exit $?
fi
if [[ "${1:-}" == "__self_test_json_validate__" ]]; then
  local_schema="${3:-$SELFTEST_SCHEMA_VERSION}"
  local_validator="${4:-$VALIDATOR_VERSION}"
  local_checksum_mode="${5:---verify-checksum}"

  if [[ "$local_validator" == --* ]]; then
    local_checksum_mode="$local_validator"
    local_validator="$VALIDATOR_VERSION"
  fi

  if [[ "$#" -gt 5 ]]; then
    emit_validator_fail_line "unexpected_extra_args" "verify" "extra_args_count=$(($# - 5))" "first_extra_arg=${6:-}"
    exit 2
  fi

  validate_selftest_jsonl "${2:-}" "$local_schema" "$local_validator" "$local_checksum_mode"
  exit $?
fi
if [[ "${1:-}" == "__pat_check_env__" ]]; then
  check_pat_env "${2:-}"
  exit $?
fi

container_ip="$(get_container_ip)"
if [[ -z "$container_ip" ]]; then
  echo "[error] unable to resolve container IP for $CONTAINER"
  exit 1
fi
nft_tag="cella_tproxy_$(sanitize_tag "$container_ip")"

# Best-effort cleanup stale rules from previous interrupted runs.
remove_nft_tag_rules "$nft_tag"

echo "[1/6] preflight port check (:$PORT)"
reclaim_proxy_port_if_needed

if [[ -z "${!PAT_ENV_KEY:-}" ]]; then
  export "$PAT_ENV_KEY"="ghu_dummy_for_e2e_cycle"
  pat_injected_dummy=1
  echo "[info] $PAT_ENV_KEY unset; injected dummy PAT for replacement-path validation"
fi

pat_shape_kind="$(detect_pat_shape_kind "${!PAT_ENV_KEY:-}")"
if is_dummy_pat_value "${!PAT_ENV_KEY:-}"; then
  pat_detected_dummy=1
  if [[ "$pat_injected_dummy" != "1" ]]; then
    echo "[warn] $PAT_ENV_KEY looks like dummy/placeholder PAT; auto-run will be blocked"
  fi
elif ! is_plausible_pat_shape "${!PAT_ENV_KEY:-}"; then
  pat_shape_invalid=1
  echo "[warn] $PAT_ENV_KEY does not match known GitHub PAT prefix/length; auto-run will be blocked"
fi

echo "[2/6] build proxy binary -> $PROXY_BIN"
(
  cd "$repo_root"
  go build -o "$PROXY_BIN" ./cmd
)

echo "[3/6] start proxy (container=$CONTAINER ip=$container_ip port=$PORT)"
(
  cd "$repo_root"
  "$PROXY_BIN" proxy \
    --container "$CONTAINER" \
    --port "$PORT" \
    --mitm \
    --auto-approve \
    --pat-env "$PAT_ENV_KEY" \
    --token-id "$TOKEN_ID" \
    --pool "$POOL" \
    --verbose
) >"$LOG_FILE" 2>&1 &
proxy_pid="$!"

ready=0
for _ in $(seq 1 "$START_TIMEOUT_SEC"); do
  if grep -q "transparent proxy listening" "$LOG_FILE" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$proxy_pid" 2>/dev/null; then
    echo "[error] proxy exited before ready"
    tail -n 120 "$LOG_FILE" || true
    exit 2
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "[error] proxy did not become ready in ${START_TIMEOUT_SEC}s"
  tail -n 120 "$LOG_FILE" || true
  exit 3
fi

echo "[4/6] trigger dummy-token exchange from container"
set +e
http_code="$(lxc exec "$CONTAINER" -- sh -lc "rm -f '$REMOTE_BODY_FILE'; curl -ksS --max-time $CURL_TIMEOUT_SEC -o '$REMOTE_BODY_FILE' -w '%{http_code}' -H 'Authorization: Bearer dummy-token' https://api.github.com/copilot_internal/v2/token")"
curl_exit_code=$?
set -e

if [[ "$curl_exit_code" -ne 0 ]]; then
  echo "[error] container curl failed (exit=$curl_exit_code)"
  tail -n 120 "$LOG_FILE" || true
  exit 11
fi

lxc exec "$CONTAINER" -- sh -lc "cat '$REMOTE_BODY_FILE'" >"$BODY_FILE" 2>/dev/null || true
if [[ ! -s "$BODY_FILE" ]]; then
  echo "[warn] empty token response body (remote file: $REMOTE_BODY_FILE)"
fi

if lxc exec "$CONTAINER" -- sh -lc "rm -f '$REMOTE_BODY_FILE'" >/dev/null 2>&1; then
  remote_body_cleanup_status="ok"
else
  remote_body_cleanup_status="failed"
  echo "[warn] failed to cleanup remote body file: $REMOTE_BODY_FILE"
fi

sleep 2
audit_line="$(grep '\[audit\].*path=/copilot_internal/v2/token' "$LOG_FILE" | tail -n 1 || true)"
if [[ -z "$audit_line" ]]; then
  echo "[error] no copilot token exchange audit line found"
  tail -n 120 "$LOG_FILE" || true
  exit 4
fi

audit_code="$(sed -n 's/.* code=\([0-9][0-9]*\) .*/\1/p' <<<"$audit_line")"
broker_token="$(sed -n 's/.* broker_token=\([^ ]*\) broker_src=.*/\1/p' <<<"$audit_line")"
broker_src="$(sed -n 's/.* broker_src=\([^ ]*\) latency=.*/\1/p' <<<"$audit_line")"

if [[ "$http_code" =~ ^[0-9]{3}$ ]] && [[ "$audit_code" =~ ^[0-9]{3}$ ]] && [[ "$http_code" != "$audit_code" ]]; then
  http_audit_mismatch=1
fi

broker_line="$(grep "\[broker\].* token=${TOKEN_ID} " "$LOG_FILE" | tail -n 1 || true)"
session_state="$(sed -n 's/.* session_state=\([^ ]*\) .*/\1/p' <<<"$broker_line")"
last_test="$(sed -n 's/.* last_test=\([^ ]*\) .*/\1/p' <<<"$broker_line")"
classification="$(classify_e2e_result "$audit_code" "$broker_src" "$session_state" "$last_test")"
action_hint="$(action_hint_for_classification "$classification")"
precheck_cmd="$(precheck_cmd_for_action_hint "$action_hint")"
run_cmd="$(run_cmd_for_action_hint "$action_hint")"
stop_conditions="$(stop_conditions_for_action_hint "$action_hint")"
precheck_skipped_reason=""
if should_skip_precheck "$action_hint" "$pat_injected_dummy"; then
  precheck_failed=0
  precheck_failed_cmds=""
  precheck_failed_outputs=""
  precheck_failed_rcs=""
  precheck_failed_kinds=""
  precheck_skipped_reason="dummy_pat_injected"
else
  run_precheck_commands "$precheck_cmd"
fi
precheck_failure_class="$(classify_precheck_failure "$precheck_skipped_reason" "$precheck_failed" "$precheck_failed_kinds" "$precheck_failed_rcs")"
auto_run_blocker_code="$(resolve_auto_run_blocker_code "$pat_injected_dummy" "$precheck_failed" "$classification")"
cycle_outcome="$(classify_cycle_outcome "$auto_run_blocker_code" "$classification")"
goal_state="$(classify_goal_state "$cycle_outcome")"
goal_state_reached="$(goal_state_reached_of "$goal_state")"
next_action="$(classify_next_action "$cycle_outcome" "$precheck_failure_class" "$action_hint")"
next_action_cmd="$(next_action_cmd_for_next_action "$next_action")"
next_action_steps="$(count_nonempty_lines "$next_action_cmd")"
next_action_auto_runnable="$(next_action_cmd_auto_runnable "$next_action_cmd")"
next_action_auto_run_blocker="$(next_action_cmd_blocker "$next_action_cmd")"
next_action_template_vars="$(next_action_template_vars_of "$next_action_cmd")"
next_action_template_var_count="$(next_action_template_var_count_of "$next_action_template_vars")"
next_action_missing_inputs="$(next_action_missing_inputs_of "$next_action_template_vars")"
next_action_missing_input_count="$(next_action_missing_input_count_of "$next_action_missing_inputs")"
next_action_missing_input_env_keys="$(next_action_missing_input_env_keys_of "$next_action_missing_inputs")"
next_action_missing_input_env_key_count="$(next_action_missing_input_env_key_count_of "$next_action_missing_input_env_keys")"
next_action_missing_secret_env_keys="$(next_action_missing_secret_env_keys_of "$next_action_missing_input_env_keys")"
next_action_missing_secret_env_key_count="$(next_action_missing_secret_env_key_count_of "$next_action_missing_secret_env_keys")"
next_action_missing_input_export_cmds="$(next_action_missing_input_export_cmds_of "$next_action_missing_input_env_keys")"
next_action_missing_input_export_cmd_count="$(next_action_missing_input_export_cmd_count_of "$next_action_missing_input_export_cmds")"
next_action_env_ref_cmds="$(next_action_env_ref_cmds_of "$next_action_cmd")"
next_action_env_ref_cmd_count="$(next_action_env_ref_cmd_count_of "$next_action_env_ref_cmds")"
next_action_ready_cmds="$(next_action_ready_cmds_of "$next_action_missing_input_export_cmds" "$next_action_env_ref_cmds")"
next_action_ready_cmd_count="$(next_action_ready_cmd_count_of "$next_action_ready_cmds")"
next_action_ready_cmd_hash="$(next_action_cmd_hash_of "$next_action_ready_cmds")"
next_action_ready_cmd_blocker="$(next_action_ready_cmd_blocker_of "$next_action_ready_cmds")"
next_action_ready_cmd_auto_runnable="$(next_action_ready_cmd_auto_runnable_of "$next_action_ready_cmds")"
next_action_ready_prereq_cmds="$(next_action_ready_prereq_cmds_of "$next_action_missing_secret_env_keys" "$PAT_ENV_KEY" "$repo_root")"
next_action_ready_prereq_cmd_count="$(next_action_ready_prereq_cmd_count_of "$next_action_ready_prereq_cmds")"
next_action_ready_prereq_cmd_hash="$(next_action_cmd_hash_of "$next_action_ready_prereq_cmds")"
next_action_execute_cmds="$(next_action_execute_cmds_of "$next_action_ready_prereq_cmds" "$next_action_ready_cmds")"
next_action_execute_cmd_count="$(next_action_execute_cmd_count_of "$next_action_execute_cmds")"
next_action_execute_cmd_hash="$(next_action_cmd_hash_of "$next_action_execute_cmds")"
next_action_execute_cmd_blocker="$(next_action_execute_cmd_blocker_of "$next_action_execute_cmds")"
next_action_execute_cmd_auto_runnable="$(next_action_execute_cmd_auto_runnable_of "$next_action_execute_cmds")"
next_action_execute_env_ref_cmds="$(next_action_execute_env_ref_cmds_of "$next_action_ready_prereq_cmds" "$next_action_env_ref_cmds" "$PAT_ENV_KEY" "$repo_root")"
next_action_execute_env_ref_cmd_count="$(next_action_execute_cmd_count_of "$next_action_execute_env_ref_cmds")"
next_action_execute_env_ref_cmd_hash="$(next_action_cmd_hash_of "$next_action_execute_env_ref_cmds")"
next_action_execute_env_ref_cmd_blocker="$(next_action_execute_cmd_blocker_of "$next_action_execute_env_ref_cmds")"
next_action_execute_env_ref_cmd_auto_runnable="$(next_action_execute_cmd_auto_runnable_of "$next_action_execute_env_ref_cmds")"
next_action_best_auto_cmd_source="$(next_action_best_auto_cmd_source_of "$next_action_execute_env_ref_cmd_auto_runnable" "$next_action_execute_cmd_auto_runnable" "$next_action_ready_cmd_auto_runnable")"
next_action_best_auto_cmds="$(next_action_best_auto_cmds_of "$next_action_best_auto_cmd_source" "$next_action_execute_env_ref_cmds" "$next_action_execute_cmds" "$next_action_ready_cmds")"
next_action_best_auto_cmd_count="$(count_nonempty_lines "$next_action_best_auto_cmds")"
next_action_best_auto_cmd_hash="$(next_action_cmd_hash_of "$next_action_best_auto_cmds")"
next_action_best_auto_cmd_blocker="$(next_action_best_auto_cmd_blocker_of "$next_action_best_auto_cmds")"
next_action_best_auto_cmd_auto_runnable="$(next_action_best_auto_cmd_auto_runnable_of "$next_action_best_auto_cmds")"
next_action_best_auto_cmd_dispatch_mode="$(next_action_best_auto_cmd_dispatch_mode_of "$next_action_best_auto_cmd_auto_runnable" "$next_action_best_auto_cmd_blocker")"
next_action_requires_manual_input="$(next_action_requires_manual_input_of "$next_action_template_var_count")"
next_action_dispatch_mode="$(classify_next_action_dispatch_mode "$next_action_auto_runnable" "$next_action_requires_manual_input" "$next_action_auto_run_blocker")"
next_action_cmd_hash="$(next_action_cmd_hash_of "$next_action_cmd")"
stop_reason="$auto_run_blocker_code"
if [[ -n "$auto_run_blocker_code" ]]; then
  can_auto_run=0
else
  can_auto_run=1
fi
precheck_steps="$(printf '%s\n' "$precheck_cmd" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
precheck_executed_steps="$(effective_precheck_steps "$precheck_steps" "$precheck_skipped_reason")"
run_steps="$(printf '%s\n' "$run_cmd" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"

echo "[5/6] observed audit"
echo "  curl_exit_code(container curl): ${curl_exit_code:-unknown}"
echo "  http_code(container curl): ${http_code:-unknown}"
echo "  audit_code(proxy): ${audit_code:-unknown}"
echo "  broker_token: ${broker_token:-missing}"
echo "  broker_src: ${broker_src:-missing}"
echo "  session_state: ${session_state:-missing}"
echo "  last_test: ${last_test:-missing}"
echo "  classification: ${classification}"
echo "  action_hint: ${action_hint}"
echo "  precheck_steps(total): ${precheck_steps}"
echo "  precheck_steps(executed): ${precheck_executed_steps}"
echo "  run_steps: ${run_steps}"
echo "  pat_detected_dummy: ${pat_detected_dummy}"
echo "  pat_shape_kind: ${pat_shape_kind}"
echo "  pat_shape_invalid: ${pat_shape_invalid}"
echo "  http_audit_mismatch: ${http_audit_mismatch}"
echo "  precheck_skipped_reason: ${precheck_skipped_reason:-none}"
echo "  precheck_failure_class: ${precheck_failure_class}"
echo "  precheck_failed: ${precheck_failed}"
if [[ "$precheck_failed" == "1" ]]; then
  echo "  precheck_failed_cmds: ${precheck_failed_cmds}"
  echo "  precheck_failed_rcs: ${precheck_failed_rcs}"
  echo "  precheck_failed_kinds: ${precheck_failed_kinds}"
  echo "  precheck_failed_outputs: ${precheck_failed_outputs}"
fi
echo "  auto_run_blocker_code: ${auto_run_blocker_code:-none}"
echo "  cycle_outcome: ${cycle_outcome}"
echo "  goal_state: ${goal_state}"
echo "  goal_state_reached: ${goal_state_reached}"
echo "  next_action: ${next_action}"
echo "  next_action_steps: ${next_action_steps}"
echo "  next_action_auto_runnable: ${next_action_auto_runnable}"
echo "  next_action_auto_run_blocker: ${next_action_auto_run_blocker}"
echo "  next_action_template_var_count: ${next_action_template_var_count}"
echo "  next_action_missing_input_count: ${next_action_missing_input_count}"
echo "  next_action_missing_input_env_key_count: ${next_action_missing_input_env_key_count}"
echo "  next_action_missing_secret_env_key_count: ${next_action_missing_secret_env_key_count}"
echo "  next_action_missing_input_export_cmd_count: ${next_action_missing_input_export_cmd_count}"
echo "  next_action_env_ref_cmd_count: ${next_action_env_ref_cmd_count}"
echo "  next_action_ready_cmd_count: ${next_action_ready_cmd_count}"
echo "  next_action_ready_cmd_hash: ${next_action_ready_cmd_hash}"
echo "  next_action_ready_cmd_blocker: ${next_action_ready_cmd_blocker}"
echo "  next_action_ready_cmd_auto_runnable: ${next_action_ready_cmd_auto_runnable}"
echo "  next_action_ready_prereq_cmd_count: ${next_action_ready_prereq_cmd_count}"
echo "  next_action_ready_prereq_cmd_hash: ${next_action_ready_prereq_cmd_hash}"
echo "  next_action_execute_cmd_count: ${next_action_execute_cmd_count}"
echo "  next_action_execute_cmd_hash: ${next_action_execute_cmd_hash}"
echo "  next_action_execute_cmd_blocker: ${next_action_execute_cmd_blocker}"
echo "  next_action_execute_cmd_auto_runnable: ${next_action_execute_cmd_auto_runnable}"
echo "  next_action_execute_env_ref_cmd_count: ${next_action_execute_env_ref_cmd_count}"
echo "  next_action_execute_env_ref_cmd_hash: ${next_action_execute_env_ref_cmd_hash}"
echo "  next_action_execute_env_ref_cmd_blocker: ${next_action_execute_env_ref_cmd_blocker}"
echo "  next_action_execute_env_ref_cmd_auto_runnable: ${next_action_execute_env_ref_cmd_auto_runnable}"
echo "  next_action_best_auto_cmd_source: ${next_action_best_auto_cmd_source}"
echo "  next_action_best_auto_cmd_count: ${next_action_best_auto_cmd_count}"
echo "  next_action_best_auto_cmd_hash: ${next_action_best_auto_cmd_hash}"
echo "  next_action_best_auto_cmd_blocker: ${next_action_best_auto_cmd_blocker}"
echo "  next_action_best_auto_cmd_auto_runnable: ${next_action_best_auto_cmd_auto_runnable}"
echo "  next_action_best_auto_cmd_dispatch_mode: ${next_action_best_auto_cmd_dispatch_mode}"
echo "  next_action_requires_manual_input: ${next_action_requires_manual_input}"
echo "  next_action_dispatch_mode: ${next_action_dispatch_mode}"
echo "  next_action_template_vars: ${next_action_template_vars}"
echo "  next_action_missing_inputs: ${next_action_missing_inputs}"
echo "  next_action_missing_input_env_keys: ${next_action_missing_input_env_keys}"
echo "  next_action_missing_secret_env_keys: ${next_action_missing_secret_env_keys}"
echo "  next_action_missing_input_export_cmds: ${next_action_missing_input_export_cmds}"
echo "  next_action_env_ref_cmds: ${next_action_env_ref_cmds}"
echo "  next_action_ready_prereq_cmds: ${next_action_ready_prereq_cmds}"
echo "  next_action_ready_cmds: ${next_action_ready_cmds}"
echo "  next_action_execute_cmds: ${next_action_execute_cmds}"
echo "  next_action_execute_env_ref_cmds: ${next_action_execute_env_ref_cmds}"
echo "  next_action_best_auto_cmds: ${next_action_best_auto_cmds}"
echo "  next_action_cmd_hash: ${next_action_cmd_hash}"
echo "  next_action_cmd: ${next_action_cmd}"
echo "  can_auto_run: ${can_auto_run}"
echo "  stop_reason: ${stop_reason:-none}"
echo "  stop_conditions: ${stop_conditions}"
echo "  precheck_cmd: ${precheck_cmd}"
echo "  run_cmd: ${run_cmd}"
echo "  nft_tag: $nft_tag"
echo "  log: $LOG_FILE"
echo "  body(local): $BODY_FILE"
echo "  body(remote): $REMOTE_BODY_FILE"
echo "  body_remote_cleanup: ${remote_body_cleanup_status}"

if [[ -z "$broker_src" || "$broker_src" == "-" ]]; then
  echo "[error] broker_src missing; replacement-path evidence incomplete"
  exit 5
fi
if [[ -z "$broker_token" || "$broker_token" == "-" ]]; then
  echo "[error] broker_token missing; broker selection evidence incomplete"
  exit 6
fi
if [[ "$broker_token" != "$TOKEN_ID" ]]; then
  echo "[error] broker_token mismatch: expected=$TOKEN_ID got=$broker_token"
  exit 7
fi
if [[ -z "$session_state" || "$session_state" == "-" ]]; then
  echo "[error] session_state missing from broker verbose snapshot"
  tail -n 120 "$LOG_FILE" || true
  exit 10
fi
if [[ "$classification" == "needs_manual_review" ]]; then
  echo "[warn] classification=needs_manual_review (check audit/session_state manually)"
fi
if [[ "$http_audit_mismatch" == "1" ]]; then
  echo "[warn] http/audit code mismatch detected (http_code=$http_code audit_code=$audit_code)"
fi
if [[ "$precheck_failed" == "1" ]]; then
  echo "[warn] precheck commands failed; blocker=${auto_run_blocker_code}"
fi
if [[ "$can_auto_run" != "1" ]]; then
  echo "[warn] auto-run disabled by stop condition: ${stop_reason}"
fi

echo "[6/6] stop proxy + verify nft cleanup"
graceful_stop_proxy

if nft_chain_dump | grep -q "$nft_tag"; then
  echo "[error] nft redirect cleanup failed; residual rule tag found: $nft_tag"
  nft_chain_dump | grep "$nft_tag" || true
  exit 8
fi

SUMMARY_FILE="$SUMMARY_FILE" \
CONTAINER="$CONTAINER" \
CONTAINER_IP="$container_ip" \
CURL_EXIT_CODE="$curl_exit_code" \
HTTP_CODE="$http_code" \
AUDIT_CODE="$audit_code" \
BROKER_TOKEN="$broker_token" \
BROKER_SRC="$broker_src" \
SESSION_STATE="$session_state" \
LAST_TEST="$last_test" \
CLASSIFICATION="$classification" \
ACTION_HINT="$action_hint" \
PRECHECK_CMD="$precheck_cmd" \
RUN_CMD="$run_cmd" \
PRECHECK_FAILED="$precheck_failed" \
PRECHECK_FAILED_CMDS="$precheck_failed_cmds" \
PRECHECK_FAILED_RCS="$precheck_failed_rcs" \
PRECHECK_FAILED_KINDS="$precheck_failed_kinds" \
PRECHECK_FAILED_OUTPUTS="$precheck_failed_outputs" \
AUTO_RUN_BLOCKER_CODE="$auto_run_blocker_code" \
CYCLE_OUTCOME="$cycle_outcome" \
GOAL_STATE="$goal_state" \
GOAL_STATE_REACHED="$goal_state_reached" \
NEXT_ACTION="$next_action" \
NEXT_ACTION_CMD="$next_action_cmd" \
NEXT_ACTION_STEPS="$next_action_steps" \
NEXT_ACTION_AUTO_RUNNABLE="$next_action_auto_runnable" \
NEXT_ACTION_AUTO_RUN_BLOCKER="$next_action_auto_run_blocker" \
NEXT_ACTION_TEMPLATE_VARS="$next_action_template_vars" \
NEXT_ACTION_TEMPLATE_VAR_COUNT="$next_action_template_var_count" \
NEXT_ACTION_MISSING_INPUTS="$next_action_missing_inputs" \
NEXT_ACTION_MISSING_INPUT_COUNT="$next_action_missing_input_count" \
NEXT_ACTION_MISSING_INPUT_ENV_KEYS="$next_action_missing_input_env_keys" \
NEXT_ACTION_MISSING_INPUT_ENV_KEY_COUNT="$next_action_missing_input_env_key_count" \
NEXT_ACTION_MISSING_SECRET_ENV_KEYS="$next_action_missing_secret_env_keys" \
NEXT_ACTION_MISSING_SECRET_ENV_KEY_COUNT="$next_action_missing_secret_env_key_count" \
NEXT_ACTION_MISSING_INPUT_EXPORT_CMDS="$next_action_missing_input_export_cmds" \
NEXT_ACTION_MISSING_INPUT_EXPORT_CMD_COUNT="$next_action_missing_input_export_cmd_count" \
NEXT_ACTION_ENV_REF_CMDS="$next_action_env_ref_cmds" \
NEXT_ACTION_ENV_REF_CMD_COUNT="$next_action_env_ref_cmd_count" \
NEXT_ACTION_READY_CMDS="$next_action_ready_cmds" \
NEXT_ACTION_READY_CMD_COUNT="$next_action_ready_cmd_count" \
NEXT_ACTION_READY_CMD_HASH="$next_action_ready_cmd_hash" \
NEXT_ACTION_READY_CMD_BLOCKER="$next_action_ready_cmd_blocker" \
NEXT_ACTION_READY_CMD_AUTO_RUNNABLE="$next_action_ready_cmd_auto_runnable" \
NEXT_ACTION_READY_PREREQ_CMDS="$next_action_ready_prereq_cmds" \
NEXT_ACTION_READY_PREREQ_CMD_COUNT="$next_action_ready_prereq_cmd_count" \
NEXT_ACTION_READY_PREREQ_CMD_HASH="$next_action_ready_prereq_cmd_hash" \
NEXT_ACTION_EXECUTE_CMDS="$next_action_execute_cmds" \
NEXT_ACTION_EXECUTE_CMD_COUNT="$next_action_execute_cmd_count" \
NEXT_ACTION_EXECUTE_CMD_HASH="$next_action_execute_cmd_hash" \
NEXT_ACTION_EXECUTE_CMD_BLOCKER="$next_action_execute_cmd_blocker" \
NEXT_ACTION_EXECUTE_CMD_AUTO_RUNNABLE="$next_action_execute_cmd_auto_runnable" \
NEXT_ACTION_EXECUTE_ENV_REF_CMDS="$next_action_execute_env_ref_cmds" \
NEXT_ACTION_EXECUTE_ENV_REF_CMD_COUNT="$next_action_execute_env_ref_cmd_count" \
NEXT_ACTION_EXECUTE_ENV_REF_CMD_HASH="$next_action_execute_env_ref_cmd_hash" \
NEXT_ACTION_EXECUTE_ENV_REF_CMD_BLOCKER="$next_action_execute_env_ref_cmd_blocker" \
NEXT_ACTION_EXECUTE_ENV_REF_CMD_AUTO_RUNNABLE="$next_action_execute_env_ref_cmd_auto_runnable" \
NEXT_ACTION_BEST_AUTO_CMD_SOURCE="$next_action_best_auto_cmd_source" \
NEXT_ACTION_BEST_AUTO_CMDS="$next_action_best_auto_cmds" \
NEXT_ACTION_BEST_AUTO_CMD_COUNT="$next_action_best_auto_cmd_count" \
NEXT_ACTION_BEST_AUTO_CMD_HASH="$next_action_best_auto_cmd_hash" \
NEXT_ACTION_BEST_AUTO_CMD_BLOCKER="$next_action_best_auto_cmd_blocker" \
NEXT_ACTION_BEST_AUTO_CMD_AUTO_RUNNABLE="$next_action_best_auto_cmd_auto_runnable" \
NEXT_ACTION_BEST_AUTO_CMD_DISPATCH_MODE="$next_action_best_auto_cmd_dispatch_mode" \
NEXT_ACTION_REQUIRES_MANUAL_INPUT="$next_action_requires_manual_input" \
NEXT_ACTION_DISPATCH_MODE="$next_action_dispatch_mode" \
NEXT_ACTION_CMD_HASH="$next_action_cmd_hash" \
STOP_CONDITIONS="$stop_conditions" \
STOP_REASON="$stop_reason" \
CAN_AUTO_RUN="$can_auto_run" \
PAT_INJECTED_DUMMY="$pat_injected_dummy" \
PAT_DETECTED_DUMMY="$pat_detected_dummy" \
PAT_SHAPE_KIND="$pat_shape_kind" \
PAT_SHAPE_INVALID="$pat_shape_invalid" \
HTTP_AUDIT_MISMATCH="$http_audit_mismatch" \
PRECHECK_SKIPPED_REASON="$precheck_skipped_reason" \
PRECHECK_FAILURE_CLASS="$precheck_failure_class" \
PRECHECK_STEPS="$precheck_steps" \
PRECHECK_EXECUTED_STEPS="$precheck_executed_steps" \
RUN_STEPS="$run_steps" \
LOG_PATH="$LOG_FILE" \
BODY_PATH="$BODY_FILE" \
REMOTE_BODY_PATH="$REMOTE_BODY_FILE" \
REMOTE_BODY_CLEANUP_STATUS="$remote_body_cleanup_status" \
SUMMARY_SCHEMA_VERSION="$SUMMARY_SCHEMA_VERSION" \
SUMMARY_COMPAT_MIN_SCHEMA="$SUMMARY_COMPAT_MIN_SCHEMA" \
VALIDATOR_VERSION="$VALIDATOR_VERSION" \
VALIDATOR_COMPAT_MIN_VERSION="$VALIDATOR_COMPAT_MIN_VERSION" \
python3 - <<'PY'
import json
import os


def split_cmds(raw: str):
    return [line.strip() for line in raw.splitlines() if line.strip()]

summary = {
    "schema_version": os.environ.get("SUMMARY_SCHEMA_VERSION", ""),
    "compat_min_schema": os.environ.get("SUMMARY_COMPAT_MIN_SCHEMA", ""),
    "validator_version": os.environ.get("VALIDATOR_VERSION", ""),
    "compat_min_validator_version": os.environ.get("VALIDATOR_COMPAT_MIN_VERSION", ""),
    "container": os.environ["CONTAINER"],
    "container_ip": os.environ["CONTAINER_IP"],
    "curl_exit_code": int(os.environ.get("CURL_EXIT_CODE", "0") or "0"),
    "http_code": os.environ.get("HTTP_CODE", ""),
    "audit_code": os.environ.get("AUDIT_CODE", ""),
    "broker_token": os.environ.get("BROKER_TOKEN", ""),
    "broker_src": os.environ.get("BROKER_SRC", ""),
    "session_state": os.environ.get("SESSION_STATE", ""),
    "last_test": os.environ.get("LAST_TEST", ""),
    "classification": os.environ.get("CLASSIFICATION", ""),
    "action_hint": os.environ.get("ACTION_HINT", ""),
    "precheck_cmd": os.environ.get("PRECHECK_CMD", ""),
    "run_cmd": os.environ.get("RUN_CMD", ""),
    "precheck_cmds": split_cmds(os.environ.get("PRECHECK_CMD", "")),
    "run_cmds": split_cmds(os.environ.get("RUN_CMD", "")),
    "precheck_failed": os.environ.get("PRECHECK_FAILED", "0") == "1",
    "precheck_failed_cmds": split_cmds(os.environ.get("PRECHECK_FAILED_CMDS", "")),
    "precheck_failed_rcs": split_cmds(os.environ.get("PRECHECK_FAILED_RCS", "")),
    "precheck_failed_kinds": split_cmds(os.environ.get("PRECHECK_FAILED_KINDS", "")),
    "precheck_failed_outputs": split_cmds(os.environ.get("PRECHECK_FAILED_OUTPUTS", "")),
    "auto_run_blocker_code": os.environ.get("AUTO_RUN_BLOCKER_CODE", ""),
    "cycle_outcome": os.environ.get("CYCLE_OUTCOME", ""),
    "goal_state": os.environ.get("GOAL_STATE", "not_reached"),
    "goal_state_reached": os.environ.get("GOAL_STATE_REACHED", "0") == "1",
    "next_action": os.environ.get("NEXT_ACTION", ""),
    "next_action_cmd": os.environ.get("NEXT_ACTION_CMD", ""),
    "next_action_cmds": split_cmds(os.environ.get("NEXT_ACTION_CMD", "")),
    "next_action_steps": int(os.environ.get("NEXT_ACTION_STEPS", "0") or "0"),
    "next_action_auto_runnable": os.environ.get("NEXT_ACTION_AUTO_RUNNABLE", "0") == "1",
    "next_action_auto_run_blocker": os.environ.get("NEXT_ACTION_AUTO_RUN_BLOCKER", ""),
    "next_action_template_vars": split_cmds(os.environ.get("NEXT_ACTION_TEMPLATE_VARS", "")),
    "next_action_template_var_count": int(os.environ.get("NEXT_ACTION_TEMPLATE_VAR_COUNT", "0") or "0"),
    "next_action_missing_inputs": split_cmds(os.environ.get("NEXT_ACTION_MISSING_INPUTS", "")),
    "next_action_missing_input_count": int(os.environ.get("NEXT_ACTION_MISSING_INPUT_COUNT", "0") or "0"),
    "next_action_missing_input_env_keys": split_cmds(os.environ.get("NEXT_ACTION_MISSING_INPUT_ENV_KEYS", "")),
    "next_action_missing_input_env_key_count": int(os.environ.get("NEXT_ACTION_MISSING_INPUT_ENV_KEY_COUNT", "0") or "0"),
    "next_action_missing_secret_env_keys": split_cmds(os.environ.get("NEXT_ACTION_MISSING_SECRET_ENV_KEYS", "")),
    "next_action_missing_secret_env_key_count": int(os.environ.get("NEXT_ACTION_MISSING_SECRET_ENV_KEY_COUNT", "0") or "0"),
    "next_action_missing_input_export_cmds": split_cmds(os.environ.get("NEXT_ACTION_MISSING_INPUT_EXPORT_CMDS", "")),
    "next_action_missing_input_export_cmd_count": int(os.environ.get("NEXT_ACTION_MISSING_INPUT_EXPORT_CMD_COUNT", "0") or "0"),
    "next_action_env_ref_cmds": split_cmds(os.environ.get("NEXT_ACTION_ENV_REF_CMDS", "")),
    "next_action_env_ref_cmd_count": int(os.environ.get("NEXT_ACTION_ENV_REF_CMD_COUNT", "0") or "0"),
    "next_action_ready_cmds": split_cmds(os.environ.get("NEXT_ACTION_READY_CMDS", "")),
    "next_action_ready_cmd_count": int(os.environ.get("NEXT_ACTION_READY_CMD_COUNT", "0") or "0"),
    "next_action_ready_cmd_hash": os.environ.get("NEXT_ACTION_READY_CMD_HASH", ""),
    "next_action_ready_cmd_blocker": os.environ.get("NEXT_ACTION_READY_CMD_BLOCKER", ""),
    "next_action_ready_cmd_auto_runnable": os.environ.get("NEXT_ACTION_READY_CMD_AUTO_RUNNABLE", "0") == "1",
    "next_action_ready_prereq_cmds": split_cmds(os.environ.get("NEXT_ACTION_READY_PREREQ_CMDS", "")),
    "next_action_ready_prereq_cmd_count": int(os.environ.get("NEXT_ACTION_READY_PREREQ_CMD_COUNT", "0") or "0"),
    "next_action_ready_prereq_cmd_hash": os.environ.get("NEXT_ACTION_READY_PREREQ_CMD_HASH", ""),
    "next_action_execute_cmds": split_cmds(os.environ.get("NEXT_ACTION_EXECUTE_CMDS", "")),
    "next_action_execute_cmd_count": int(os.environ.get("NEXT_ACTION_EXECUTE_CMD_COUNT", "0") or "0"),
    "next_action_execute_cmd_hash": os.environ.get("NEXT_ACTION_EXECUTE_CMD_HASH", ""),
    "next_action_execute_cmd_blocker": os.environ.get("NEXT_ACTION_EXECUTE_CMD_BLOCKER", ""),
    "next_action_execute_cmd_auto_runnable": os.environ.get("NEXT_ACTION_EXECUTE_CMD_AUTO_RUNNABLE", "0") == "1",
    "next_action_execute_env_ref_cmds": split_cmds(os.environ.get("NEXT_ACTION_EXECUTE_ENV_REF_CMDS", "")),
    "next_action_execute_env_ref_cmd_count": int(os.environ.get("NEXT_ACTION_EXECUTE_ENV_REF_CMD_COUNT", "0") or "0"),
    "next_action_execute_env_ref_cmd_hash": os.environ.get("NEXT_ACTION_EXECUTE_ENV_REF_CMD_HASH", ""),
    "next_action_execute_env_ref_cmd_blocker": os.environ.get("NEXT_ACTION_EXECUTE_ENV_REF_CMD_BLOCKER", ""),
    "next_action_execute_env_ref_cmd_auto_runnable": os.environ.get("NEXT_ACTION_EXECUTE_ENV_REF_CMD_AUTO_RUNNABLE", "0") == "1",
    "next_action_best_auto_cmd_source": os.environ.get("NEXT_ACTION_BEST_AUTO_CMD_SOURCE", ""),
    "next_action_best_auto_cmds": split_cmds(os.environ.get("NEXT_ACTION_BEST_AUTO_CMDS", "")),
    "next_action_best_auto_cmd_count": int(os.environ.get("NEXT_ACTION_BEST_AUTO_CMD_COUNT", "0") or "0"),
    "next_action_best_auto_cmd_hash": os.environ.get("NEXT_ACTION_BEST_AUTO_CMD_HASH", ""),
    "next_action_best_auto_cmd_blocker": os.environ.get("NEXT_ACTION_BEST_AUTO_CMD_BLOCKER", ""),
    "next_action_best_auto_cmd_auto_runnable": os.environ.get("NEXT_ACTION_BEST_AUTO_CMD_AUTO_RUNNABLE", "0") == "1",
    "next_action_best_auto_cmd_dispatch_mode": os.environ.get("NEXT_ACTION_BEST_AUTO_CMD_DISPATCH_MODE", ""),
    "next_action_requires_manual_input": os.environ.get("NEXT_ACTION_REQUIRES_MANUAL_INPUT", "0") == "1",
    "next_action_dispatch_mode": os.environ.get("NEXT_ACTION_DISPATCH_MODE", ""),
    "next_action_cmd_hash": os.environ.get("NEXT_ACTION_CMD_HASH", ""),
    "stop_conditions": split_cmds(os.environ.get("STOP_CONDITIONS", "")),
    "stop_reason": os.environ.get("STOP_REASON", ""),
    "can_auto_run": os.environ.get("CAN_AUTO_RUN", "0") == "1",
    "pat_injected_dummy": os.environ.get("PAT_INJECTED_DUMMY", "0") == "1",
    "pat_detected_dummy": os.environ.get("PAT_DETECTED_DUMMY", "0") == "1",
    "pat_shape_kind": os.environ.get("PAT_SHAPE_KIND", "unknown"),
    "pat_shape_invalid": os.environ.get("PAT_SHAPE_INVALID", "0") == "1",
    "http_audit_mismatch": os.environ.get("HTTP_AUDIT_MISMATCH", "0") == "1",
    "precheck_skipped_reason": os.environ.get("PRECHECK_SKIPPED_REASON", ""),
    "precheck_failure_class": os.environ.get("PRECHECK_FAILURE_CLASS", ""),
    "precheck_steps": int(os.environ.get("PRECHECK_STEPS", "0") or "0"),
    "precheck_executed_steps": int(os.environ.get("PRECHECK_EXECUTED_STEPS", "0") or "0"),
    "run_steps": int(os.environ.get("RUN_STEPS", "0") or "0"),
    "nft_cleanup": "ok",
    "log": os.environ.get("LOG_PATH", ""),
    "body": os.environ.get("BODY_PATH", ""),
    "body_remote": os.environ.get("REMOTE_BODY_PATH", ""),
    "body_remote_cleanup": os.environ.get("REMOTE_BODY_CLEANUP_STATUS", "not_attempted"),
}

with open(os.environ["SUMMARY_FILE"], "w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)
PY

echo "PASS - dummy-token path reached broker with source metadata and nft cleanup verified"
echo "summary: $SUMMARY_FILE"
