#!/usr/bin/env bash
# Everything CI would run. The layering checks are the interesting part: ADR-006's
# rules are only real if they are a build failure rather than a code-review habit.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '   \033[32mok\033[0m  %s\n' "$*"; }
bad()  { printf '   \033[31mFAIL\033[0m %s\n' "$*"; fail=1; }

step "build (warnings are failures)"
out=$(cargo build --workspace --all-targets 2>&1)
n=$(grep -c '^warning' <<<"$out")
if [ "$n" -eq 0 ]; then ok "no warnings"; else bad "$n warnings"; grep '^warning' <<<"$out" | head -20; fi

step "layering: blktamper-core must not know about terminals or runtimes"
tree=$(cargo tree -p blktamper-core --prefix none 2>/dev/null | awk '{print $1}' | sort -u)
for forbidden in ratatui crossterm tokio anyhow arboard clap; do
  if grep -qx "$forbidden" <<<"$tree"; then
    bad "blktamper-core depends on $forbidden"
  else
    ok "no $forbidden in blktamper-core"
  fi
done

step "layering: blktamper-formats must not know about the OS or the UI"
tree=$(cargo tree -p blktamper-formats --prefix none --edges normal 2>/dev/null | awk '{print $1}' | sort -u)
for forbidden in ratatui crossterm blktamper-io; do
  if grep -qx "$forbidden" <<<"$tree"; then
    bad "blktamper-formats depends on $forbidden (dev-dependencies are fine)"
  else
    ok "no $forbidden in blktamper-formats"
  fi
done

step "layering: no terminal vocabulary below the TUI"
hits=$(grep -rnE '\b(Color|Style|Modifier|KeyCode|ratatui|crossterm)\b' \
        crates/blktamper-core/src crates/blktamper-io/src crates/blktamper-formats/src \
        2>/dev/null | grep -v '^\s*//' || true)
if [ -z "$hits" ]; then ok "model and formats are presentation-free"; else bad "terminal types leaked:"; echo "$hits" | head; fi

step "a consumer can take core + one format"
# Build is not enough: the integration tests can still reference a module that is
# configured out, which is exactly how this regressed once. Run the tests.
for feat in mbr gpt fat exfat; do
  out=$(cargo test -q -p blktamper-formats --no-default-features --features "$feat" 2>&1)
  if grep -qE '^error|FAILED' <<<"$out"; then
    bad "--features $feat does not build and test on its own"
    grep -E '^error|^---- ' <<<"$out" | head -3
  else
    n=$(grep -oE 'test result: ok\. [0-9]+' <<<"$out" | awk '{s+=$4} END {print s+0}')
    ok "--features $feat alone: $n tests"
  fi
done

step "no unsafe anywhere"
# `grep -rn` prefixes each line with file:lineno, so comment filtering has to look
# after the colon, not at the start of the line.
hits=$(grep -rn 'unsafe' crates/*/src --include='*.rs' \
        | grep -v 'forbid(unsafe_code)' \
        | grep -vE ':[[:space:]]*(//|\*)' || true)
if [ -n "$hits" ]; then bad "unsafe code found"; echo "$hits"; else ok "no unsafe"; fi

step "fixtures"
if [ -d tests/fixtures/gen ] && [ -n "$(ls -A tests/fixtures/gen 2>/dev/null)" ]; then
  ok "$(ls tests/fixtures/gen | wc -l) images present"
else
  printf '   \033[33mskip\033[0m fixtures absent; run tests/fixtures/make-fixtures.sh\n'
fi

step "clippy"
if command -v cargo-clippy >/dev/null 2>&1 || cargo clippy --version >/dev/null 2>&1; then
  out=$(cargo clippy --workspace --all-targets 2>&1)
  n=$(grep -cE '^(warning|error)' <<<"$out")
  if [ "$n" -eq 0 ]; then ok "clippy clean"; else bad "$n clippy findings"; grep -E '^(warning|error)' <<<"$out" | head -10; fi
else
  printf '   \033[33mskip\033[0m clippy not installed\n'
fi

step "tests"
out=$(cargo test --workspace 2>&1)
passed=$(grep -oE 'test result: ok\. [0-9]+' <<<"$out" | awk '{s+=$4} END {print s+0}')
failed=$(grep -cE '^test result: FAILED' <<<"$out")
if [ "$failed" -eq 0 ]; then ok "$passed tests passed"; else bad "$failed test binaries failed"; grep -E '^---- |panicked at' <<<"$out" | head -20; fi

step "read-only guarantee"
if grep -rnE '\bwrite_at\b|OpenOptions::new\(\)[^;]*\.write\(true\)|\.create\(true\)' crates/blktamper-io/src | grep -v '^\s*//'; then
  bad "blktamper-io has grown a write path; doc/07-write-safety.md must be honoured first"
else
  ok "blktamper-io still has no write path"
fi

printf '\n'
if [ "$fail" -eq 0 ]; then printf '\033[32mall checks passed\033[0m\n'; else printf '\033[31msome checks failed\033[0m\n'; fi
exit $fail
