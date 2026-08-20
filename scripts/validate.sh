#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/release.yml"

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [ -f "$ROOT/$1" ] || fail "missing $1"
}

require_text() {
  local needle="$1"
  local file="$2"
  grep -Fq -- "$needle" "$file" || fail "$(basename "$file") is missing: $needle"
}

reject_text() {
  local needle="$1"
  local file="$2"
  if grep -Fq -- "$needle" "$file"; then
    fail "$(basename "$file") contains forbidden text: $needle"
  fi
}

require_file ".github/workflows/release.yml"
require_file "README.md"
require_file "SECURITY.md"

bash -n "$0"

# PyYAML validates the YAML and then checks every run block as standalone Bash.
# BaseLoader preserves GitHub's `on` key as text instead of YAML 1.1 boolean.
python3 - "$WORKFLOW" <<'PY'
import pathlib
import os
import re
import subprocess
import sys
import tempfile

import yaml

path = pathlib.Path(sys.argv[1])
try:
    workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
except yaml.YAMLError as exc:
    raise SystemExit(f"invalid workflow YAML: {exc}")

if not isinstance(workflow, dict):
    raise SystemExit("workflow root is not a mapping")
triggers = workflow.get("on", {})
if not isinstance(triggers, dict) or set(triggers) != {"workflow_dispatch"}:
    raise SystemExit("workflow must be triggered only by workflow_dispatch")
dispatch = triggers.get("workflow_dispatch", {})
inputs = dispatch.get("inputs", {}) if isinstance(dispatch, dict) else {}
for input_name in ("ref", "version"):
    config = inputs.get(input_name)
    if not isinstance(config, dict) or config.get("required") != "true":
        raise SystemExit(f"workflow_dispatch input {input_name} is not required")
expected_defaults = {
    "ref": "v2.0.33-dev",
    "version": "2.0.33-dev",
}
for input_name, expected in expected_defaults.items():
    if inputs[input_name].get("default") != expected:
        raise SystemExit(f"workflow_dispatch input {input_name} must default to {expected}")
if workflow.get("permissions") != {"contents": "write"}:
    raise SystemExit("workflow permissions must be limited to contents: write")
jobs = workflow.get("jobs")
if not isinstance(jobs, dict) or not jobs:
    raise SystemExit("workflow has no jobs")

release_steps = jobs.get("release", {}).get("steps", [])
step_names = [step.get("name") for step in release_steps if isinstance(step, dict)]
required_order = [
    "Validate release inputs",
    "Check out the private source at the validated ref",
    "Gate 1 - release regression",
    "Gate 2 - Go tests",
    "Gate 3 - Go race detector",
    "Gate 4 - Windows vet",
    "Gate 5 - Windows build",
    "Gate 6 - Linux build",
    "Gate 7 - Go vet",
    "Gate 8 - diff check",
    "Gate 9 - all frontend and mobile tests, sequentially",
    "Derive and verify the release public key",
    "Build the embedded Linux daemon",
    "Build the stamped Windows app and NSIS installer",
    "Audit Wails-generated changes",
    "Stage and audit release assets",
    "Sign latest.json and create checksums",
    "Create or update the public release",
]
try:
    positions = [step_names.index(name) for name in required_order]
except ValueError as exc:
    raise SystemExit(f"required release step is missing: {exc}")
if positions != sorted(positions):
    raise SystemExit("release gates/build/publish steps are not sequential")

input_script = None
stamp_script = None
generated_audit_script = None
generated_audit_working_directory = None
signing_script = None
manifest_script = None
stage_script = None
publish_script = None
action_count = 0
for job_name, job in jobs.items():
    if not isinstance(job, dict):
        raise SystemExit(f"job {job_name} is not a mapping")
    steps = job.get("steps", [])
    if not isinstance(steps, list):
        raise SystemExit(f"job {job_name} steps is not a list")
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise SystemExit(f"{job_name}/step {index} is not a mapping")
        if "uses" in step:
            action_count += 1
            action = step["uses"]
            if not isinstance(action, str) or not action.startswith("actions/"):
                raise SystemExit(f"third-party action is forbidden: {action}")
        if "run" not in step:
            continue
        script = step["run"]
        if "${{ inputs." in script:
            raise SystemExit(f"untrusted input expression is interpolated directly in {job_name}/step {index}")
        if step.get("name") == "Validate release inputs":
            input_script = script
        if step.get("name") == "Build the stamped Windows app and NSIS installer":
            stamp_script = script
        if step.get("name") == "Audit Wails-generated changes":
            generated_audit_script = script
            generated_audit_working_directory = step.get("working-directory")
        if step.get("name") == "Derive and verify the release public key":
            signing_script = script
        if step.get("name") == "Stage and audit release assets":
            stage_script = script
        if step.get("name") == "Sign latest.json and create checksums":
            manifest_script = script
        if step.get("name") == "Create or update the public release":
            publish_script = script
        with tempfile.NamedTemporaryFile("w", suffix=".sh", encoding="utf-8") as handle:
            handle.write(script)
            handle.flush()
            checked = subprocess.run(
                ["bash", "-n", handle.name],
                text=True,
                capture_output=True,
                check=False,
            )
        if checked.returncode:
            name = step.get("name", f"step {index}")
            raise SystemExit(f"invalid Bash in {job_name}/{name}: {checked.stderr.strip()}")

if input_script is None:
    raise SystemExit("input validation step was not found")
if stamp_script is None:
    raise SystemExit("stamped Windows build step was not found")
if generated_audit_script is None:
    raise SystemExit("Wails generated-change audit step was not found")
if generated_audit_working_directory != "source/cmd/jayflow":
    raise SystemExit("Wails generated-change audit must resolve frontend/wailsjs/go from source/cmd/jayflow")
if publish_script is None:
    raise SystemExit("release publication step was not found")
if action_count == 0:
    raise SystemExit("workflow contains no actions to audit")

workflow_text = path.read_text(encoding="utf-8")
secret_names = set(re.findall(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*}}", workflow_text))
expected_secret_names = {
    "JAYFLOW_RELEASE_PRIVATE_KEY",
    "JAYFLOW_SOURCE_DEPLOY_KEY",
}
if secret_names != expected_secret_names:
    raise SystemExit(f"workflow secret allowlist changed: {sorted(secret_names)}")

for required_fragment in (
    'REPO_ROOT="$(git rev-parse --show-toplevel)"',
    'cd "$REPO_ROOT"',
    "git diff --name-only -z",
    "git diff --quiet --ignore-all-space --",
    "git restore --worktree --",
    "git diff --check",
    "git ls-files --others --exclude-standard -z -- frontend/wailsjs/go",
    "git diff --exit-code -- frontend/wailsjs/go",
):
    if required_fragment not in generated_audit_script:
        raise SystemExit(f"Wails generated-change audit is missing: {required_fragment}")

if "--prerelease=false" not in publish_script or '--prerelease="$PRERELEASE"' in publish_script:
    raise SystemExit("release publication must remain eligible for the latest channel")

if signing_script is None or manifest_script is None or stage_script is None:
    raise SystemExit("signing, staging, or manifest step was not found")
for required_fragment in (
    "go run ./internal/updater/signtool -pubkey",
    'echo "::add-mask::$PUBLIC_KEY"',
    'if [ "$PUBLIC_KEY" != "$EXPECTED_PUBLIC_KEY" ]',
):
    if required_fragment not in signing_script:
        raise SystemExit(f"release key verification is missing: {required_fragment}")
for required_fragment in (
    'go run ./internal/updater/signtool',
    '-version "$VERSION"',
    '-artifact "dist/JayFlow-${VERSION}.exe"',
    '-out dist/latest.json',
    "sha256sum",
):
    if required_fragment not in manifest_script:
        raise SystemExit(f"signed manifest generation is missing: {required_fragment}")

required_assets = (
    "dist/JayFlow-${VERSION}.exe",
    "dist/JayFlow-${VERSION}-setup.exe",
    "dist/JayFlow-setup.exe",
    "dist/checksums.txt",
    "dist/latest.json",
    "dist/buildinfo.txt",
)
for asset in required_assets:
    if f'"{asset}"' not in publish_script:
        raise SystemExit(f"release upload is missing asset: {asset}")
for required_fragment in (
    "gh release view",
    "gh release edit",
    "gh release create",
    "gh release upload",
    "--latest",
    "--clobber",
):
    if required_fragment not in publish_script:
        raise SystemExit(f"idempotent release publication is missing: {required_fragment}")
publish_positions = [
    publish_script.index(fragment)
    for fragment in ("gh release view", "gh release edit", "gh release create", "gh release upload")
]
if publish_positions != sorted(publish_positions):
    raise SystemExit("release view/edit/create/upload flow is out of order")
if "release delete" in workflow_text:
    raise SystemExit("release deletion is forbidden")

root = path.parents[2]
safe_env = {
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "LANG": "C.UTF-8",
}
cases = [
    ("2.0.33-dev", "v2.0.33-dev", True),
    ("2.0.33-dev", "refs/tags/v2.0.33-dev", True),
    ("2.0.33", "v2.0.33", True),
    ("0.0.0", "refs/tags/v0.0.0", True),
    ("999999.1.2-dev", "0123456789abcdef0123456789abcdef01234567", True),
    ("2.0.33", "ABCDEF0123456789ABCDEF0123456789ABCDEF01", True),
    ("v2.0.33", "v2.0.33", False),
    ("01.2.3", "v01.2.3", False),
    ("1.02.3", "v1.02.3", False),
    ("1.2.03", "v1.2.03", False),
    ("1.2.3-dev-extra", "v1.2.3-dev-extra", False),
    ("1.2.3-rc1", "v1.2.3-rc1", False),
    ("1.2.3+build", "v1.2.3+build", False),
    ("2.0.33", "main", False),
    ("2.0.33", "refs/heads/main", False),
    ("2.0.33", "feature/release", False),
    ("2.0.33", "v2.0.34", False),
    ("2.0.33-dev", "refs/tags/v2.0.33", False),
    ("2.0.33", "0123456789abcdef0123456789abcdef0123456", False),
    ("2.0.33", "0123456789abcdef0123456789abcdef012345678", False),
    ("2.0.33", "main;echo-pwn", False),
    ("2.0.33", "v2.0.33\necho-pwn", False),
]
with tempfile.NamedTemporaryFile("w", suffix=".sh", encoding="utf-8") as script_file:
    script_file.write(input_script)
    script_file.flush()
    for version, ref, should_pass in cases:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as output_file:
            env = safe_env.copy()
            env.update({
                "INPUT_VERSION": version,
                "INPUT_REF": ref,
                "GITHUB_OUTPUT": output_file.name,
            })
            checked = subprocess.run(
                ["bash", script_file.name],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            if (checked.returncode == 0) != should_pass:
                expectation = "pass" if should_pass else "fail"
                raise SystemExit(
                    f"input validation should {expectation} for version={version!r}, ref={ref!r}"
                )
            if should_pass:
                output = pathlib.Path(output_file.name).read_text(encoding="utf-8")
                expected_output = f"version={version}\nref={ref}\n"
                if output != expected_output:
                    raise SystemExit(
                        f"input validation emitted unexpected outputs for version={version!r}, ref={ref!r}"
                    )

stamp_prefix, marker, _ = stamp_script.partition("wails build")
if not marker:
    raise SystemExit("stamped Windows build step does not invoke Wails")
with tempfile.TemporaryDirectory() as temp_dir:
    config_path = pathlib.Path(temp_dir, "wails.json")
    config_path.write_text('{"info":{"productVersion":"2.0.0.0"}}\n', encoding="utf-8")
    env = safe_env.copy()
    env.update({"VERSION": "2.0.33-dev", "PUBLIC_KEY": "test-public-key"})
    checked = subprocess.run(
        ["bash", "-c", stamp_prefix],
        cwd=temp_dir,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if checked.returncode:
        raise SystemExit(f"Wails metadata stamping failed: {checked.stderr.strip()}")
    stamped = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    if stamped.get("info", {}).get("productVersion") != "2.0.33.0":
        raise SystemExit("Wails metadata did not receive the numeric Windows version")
PY

require_text "workflow_dispatch:" "$WORKFLOW"
require_text "ref:" "$WORKFLOW"
require_text "version:" "$WORKFLOW"
require_text "required: true" "$WORKFLOW"
require_text "contents: write" "$WORKFLOW"
require_text "group: public-release" "$WORKFLOW"
require_text "cancel-in-progress: false" "$WORKFLOW"
reject_text "pull_request:" "$WORKFLOW"
reject_text "release delete" "$WORKFLOW"

require_text "repository: julubileu/jayflow-v2" "$WORKFLOW"
require_text 'ssh-key: ${{ secrets.JAYFLOW_SOURCE_DEPLOY_KEY }}' "$WORKFLOW"
require_text "path: source" "$WORKFLOW"
require_text "go-version-file: source/go.mod" "$WORKFLOW"
require_text "actions/setup-node@v4" "$WORKFLOW"
require_text "node-version: '22'" "$WORKFLOW"
require_text "runs-on: ubuntu-24.04" "$WORKFLOW"
require_text "sudo apt-get install -y --no-install-recommends nsis" "$WORKFLOW"
require_text "github.com/wailsapp/wails/v2/cmd/wails@v2.14.0" "$WORKFLOW"
require_text "/usr/bin/chromium" "$WORKFLOW"
reject_text "curl " "$WORKFLOW"
reject_text "wget " "$WORKFLOW"

require_text "bash tests/release-build-regression.sh" "$WORKFLOW"
require_text "go test -count=1 ./..." "$WORKFLOW"
require_text "go test -race -count=1 ./..." "$WORKFLOW"
require_text "GOOS=windows GOARCH=amd64 go vet ./..." "$WORKFLOW"
require_text "GOOS=windows GOARCH=amd64 go build ./..." "$WORKFLOW"
require_text "GOOS=linux GOARCH=amd64 go build ./..." "$WORKFLOW"
require_text "go vet ./..." "$WORKFLOW"
require_text "git diff --check" "$WORKFLOW"
require_text "git diff --exit-code" "$WORKFLOW"
require_text "find scripts -maxdepth 1 -type f -name '*.test.mjs' -print0" "$WORKFLOW"
require_text "node scripts/mobile-shots.mjs" "$WORKFLOW"

require_text "JAYFLOW_RELEASE_PRIVATE_KEY: \${{ secrets.JAYFLOW_RELEASE_PRIVATE_KEY }}" "$WORKFLOW"
require_text "EXPECTED_PUBLIC_KEY: \${{ vars.JAYFLOW_RELEASE_PUBLIC_KEY }}" "$WORKFLOW"
require_text "go run ./internal/updater/signtool -pubkey" "$WORKFLOW"
require_text '::add-mask::$PUBLIC_KEY' "$WORKFLOW"
reject_text "release public key:" "$WORKFLOW"

require_text "-X main.Version=\${VERSION}" "$WORKFLOW"
require_text "-X main.DaemonVersion=\${VERSION} -X main.AppVersion=\${VERSION}" "$WORKFLOW"
require_text "PublicKeyBase64=\${PUBLIC_KEY}" "$WORKFLOW"
require_text "config.info.productVersion = windowsVersion;" "$WORKFLOW"
require_text "-nsis" "$WORKFLOW"
require_text "-installscope user" "$WORKFLOW"
require_text 'dist/JayFlow-${VERSION}.exe' "$WORKFLOW"
require_text 'dist/JayFlow-${VERSION}-setup.exe' "$WORKFLOW"
require_text "dist/JayFlow-setup.exe" "$WORKFLOW"
require_text "dist/checksums.txt" "$WORKFLOW"
require_text "dist/latest.json" "$WORKFLOW"
require_text 'https://github.com/julubileu/jayflow-releases/releases/download/v${VERSION}/JayFlow-${VERSION}.exe' "$WORKFLOW"

require_text "gh release view" "$WORKFLOW"
require_text "gh release edit" "$WORKFLOW"
require_text "gh release create" "$WORKFLOW"
require_text "--latest" "$WORKFLOW"
require_text "--clobber" "$WORKFLOW"
require_text "SOURCE_SHA" "$WORKFLOW"
require_text "SOURCE_REF" "$WORKFLOW"
require_text 'GH_TOKEN: ${{ github.token }}' "$WORKFLOW"
require_text "--prerelease=false" "$WORKFLOW"

ACTION_COUNT=0
while IFS= read -r action; do
  ACTION_COUNT=$((ACTION_COUNT + 1))
  case "$action" in
    actions/*) ;;
    *) fail "third-party action is forbidden: $action" ;;
  esac
done < <(sed -nE 's/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*([^[:space:]#]+).*/\2/p' "$WORKFLOW")
[ "$ACTION_COUNT" -gt 0 ] || fail "workflow contains no actions to audit"

require_text "Releases/latest" "$ROOT/README.md"
require_text "JayFlow-setup.exe" "$ROOT/README.md"
require_text "2.0.33-dev" "$ROOT/README.md"
require_text "por usuário" "$ROOT/README.md"
reject_text "instalador estável" "$ROOT/README.md"
require_text "portátil" "$ROOT/README.md"
require_text "PAT" "$ROOT/README.md"
require_text "VM" "$ROOT/README.md"
require_text "Diagnóstico" "$ROOT/README.md"
require_text "Ed25519" "$ROOT/SECURITY.md"
require_text "reporte" "$ROOT/SECURITY.md"

printf 'release repository validation passed\n'
