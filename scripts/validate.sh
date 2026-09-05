#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/release.yml"
SOURCE_REPO="${JAYFLOW_SOURCE_DIR:-$ROOT/../jayflow-v2}"

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

for required in \
  .github/workflows/release.yml \
  README.md \
  SECURITY.md \
  go.mod \
  cmd/release-tool/main.go \
  cmd/release-tool/main_test.go; do
  require_file "$required"
done
[ -d "$SOURCE_REPO/internal/updater/signtool" ] \
  || fail "private source compatibility fixture not found at $SOURCE_REPO"

bash -n "$0"

python3 - "$WORKFLOW" "$ROOT" "$SOURCE_REPO" <<'PY'
import base64
import hashlib
import json
import os
import pathlib
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

workflow_path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
source_repo = pathlib.Path(sys.argv[3])
workflow_text = workflow_path.read_text(encoding="utf-8")


def checked(command, *, cwd=root, env=None, input_text=None):
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def require_success(result, label):
    if result.returncode:
        details = result.stderr.strip() or result.stdout.strip()
        raise SystemExit(f"{label} failed: {details}")


try:
    workflow = yaml.load(workflow_text, Loader=yaml.BaseLoader)
except yaml.YAMLError as exc:
    raise SystemExit(f"invalid workflow YAML: {exc}")
if not isinstance(workflow, dict):
    raise SystemExit("workflow root is not a mapping")

triggers = workflow.get("on", {})
if not isinstance(triggers, dict) or set(triggers) != {"workflow_dispatch"}:
    raise SystemExit("workflow must be triggered only by workflow_dispatch")
dispatch = triggers["workflow_dispatch"]
inputs = dispatch.get("inputs", {}) if isinstance(dispatch, dict) else {}
for name, default in {"ref": "v2.0.33-dev", "version": "2.0.33-dev"}.items():
    config = inputs.get(name)
    if not isinstance(config, dict) or config.get("required") != "true":
        raise SystemExit(f"workflow_dispatch input {name} is not required")
    if config.get("default") != default:
        raise SystemExit(f"workflow_dispatch input {name} must default to {default}")

if workflow.get("permissions") != {"contents": "read"}:
    raise SystemExit("top-level permissions must be contents: read")
if workflow.get("concurrency") != {"group": "public-release", "cancel-in-progress": "false"}:
    raise SystemExit("release concurrency policy changed")

jobs = workflow.get("jobs")
expected_jobs = {"build_windows", "build_linux", "accept_linux", "sign_publish"}
if not isinstance(jobs, dict) or set(jobs) != expected_jobs:
    got = sorted(jobs) if isinstance(jobs, dict) else jobs
    raise SystemExit(f"workflow jobs are {got}, want {sorted(expected_jobs)}")
if jobs["accept_linux"].get("needs") != "build_linux":
    raise SystemExit("accept_linux must consume only build_linux")
if jobs["sign_publish"].get("needs") != ["build_windows", "build_linux", "accept_linux"]:
    raise SystemExit("sign_publish must wait for both builds and Linux acceptance")
for name in ("build_windows", "build_linux", "accept_linux"):
    if jobs[name].get("permissions") != {"contents": "read"}:
        raise SystemExit(f"{name} must remain read-only")
if jobs["sign_publish"].get("permissions") != {"contents": "write"}:
    raise SystemExit("sign_publish alone may write release contents")
for name in ("build_windows", "build_linux"):
    if "needs" in jobs[name]:
        raise SystemExit(f"{name} must resolve the validated tag independently and declare no needs")
for name, job in jobs.items():
    if job.get("runs-on") != "ubuntu-24.04":
        raise SystemExit(f"{name} must use the audited ubuntu-24.04 runner")
for name, timeout in (("build_linux", "45"), ("accept_linux", "30")):
    if jobs[name].get("timeout-minutes") != timeout:
        raise SystemExit(f"{name} must keep its bounded {timeout}-minute timeout")

build_windows = jobs["build_windows"]
build_linux = jobs["build_linux"]
accept_linux = jobs["accept_linux"]
sign = jobs["sign_publish"]


def serialized(value):
    return json.dumps(value, sort_keys=True)


windows_text = serialized(build_windows)
linux_text = serialized(build_linux)
accept_text = serialized(accept_linux)
sign_text = serialized(sign)
for name, text in (
    ("build_windows", windows_text),
    ("build_linux", linux_text),
    ("accept_linux", accept_text),
):
    if "JAYFLOW_RELEASE_PRIVATE_KEY" in text:
        raise SystemExit(f"release private key must never be present in {name}")
    if set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text)) != {"JAYFLOW_SOURCE_DEPLOY_KEY"}:
        raise SystemExit(f"{name} secret allowlist must contain only the read-only deploy key")
if "JAYFLOW_SOURCE_DEPLOY_KEY" in sign_text or "julubileu/jayflow-v2" in sign_text:
    raise SystemExit("sign_publish must never receive or check out private source")
if "go run" in sign_text:
    raise SystemExit("sign_publish must execute the precompiled public tool, never go run")
if set(re.findall(r"secrets\.([A-Za-z0-9_]+)", sign_text)) != {"JAYFLOW_RELEASE_PRIVATE_KEY"}:
    raise SystemExit("sign_publish secret allowlist must contain only the signing key")

windows_steps = build_windows.get("steps", [])
linux_steps = build_linux.get("steps", [])
accept_steps = accept_linux.get("steps", [])
sign_steps = sign.get("steps", [])
if not all(isinstance(steps, list) for steps in (windows_steps, linux_steps, accept_steps, sign_steps)):
    raise SystemExit("job steps must be lists")


def names(steps):
    return [step.get("name") for step in steps if isinstance(step, dict)]


def require_order(actual_names, required_names, job_name):
    try:
        positions = [actual_names.index(name) for name in required_names]
    except ValueError as exc:
        raise SystemExit(f"{job_name} required step missing: {exc}")
    if positions != sorted(positions):
        raise SystemExit(f"{job_name} required steps are out of order")


require_order(names(windows_steps), [
    "Validate release inputs",
    "Check out the private source at the validated tag",
    "Derive the reproducible source epoch",
    "Prepare the private source gate environment",
    "Gate 1 - release regression",
    "Gate 2 - Go tests",
    "Gate 3 - Go race detector",
    "Gate 4 - Windows vet",
    "Gate 5 - Windows build",
    "Gate 6 - Linux build",
    "Gate 7 - Go vet",
    "Gate 8 - diff check",
    "Gate 9 - all frontend and mobile tests, sequentially",
    "Build and audit the embedded Linux daemon",
    "Build the stamped Windows app and NSIS installer twice",
    "Audit Wails-generated changes",
    "Stage and audit the exact unsigned release assets",
    "Upload the unsigned Windows internal artifact",
    "Upload the separately audited daemon artifact",
    "Release the private gate tmpfs",
], "build_windows")
require_order(names(linux_steps), [
    "Validate release inputs",
    "Check out the private source at the validated tag",
    "Record and verify source identity",
    "Derive the reproducible source epoch",
    "Build the trusted public auditor",
    "Prepare the private source gate environment",
    "Run focused Linux release gates",
    "Build and audit reproducible Linux gateway",
    "Upload the unsigned Linux gateway",
    "Release the private gate tmpfs",
], "build_linux")
require_order(names(accept_steps), [
    "Check out the private source from the Linux build",
    "Verify accepted source identity",
    "Download the transported Linux gateway",
    "Build the acceptance daemon",
    "Audit transported Linux bytes",
    "Expose the runner browser as Chromium",
    "Install acceptance frontend dependencies",
    "Stage the acceptance inputs outside the runner home",
    "Run real-systemd and Playwright acceptance",
    "Collect acceptance diagnostics",
], "accept_linux")
require_order(names(sign_steps), [
    "Check out only the public release repository",
    "Test and compile the trusted public tool before secret injection",
    "Download the unsigned Windows internal artifact",
    "Download the separate audited daemon artifact",
    "Download the unsigned Linux gateway",
    "Reconcile independent build identities",
    "Audit downloaded bytes before signing",
    "Derive and verify the release public key",
    "Sign final bytes and generate authenticated metadata",
    "Verify signed final bundle without the private key",
    "Create or reconcile the atomic public release",
], "sign_publish")

scripts = {}
actions = []
for job_name, steps in (
    ("build_windows", windows_steps),
    ("build_linux", linux_steps),
    ("accept_linux", accept_steps),
    ("sign_publish", sign_steps),
):
    for index, step in enumerate(steps, 1):
        if not isinstance(step, dict):
            raise SystemExit(f"{job_name}/step {index} is not a mapping")
        if "uses" in step:
            actions.append((job_name, step))
        if "run" not in step:
            continue
        script = step["run"]
        if "${{ inputs." in script:
            raise SystemExit(f"untrusted inputs are directly interpolated in {job_name}/step {index}")
        scripts[step.get("name", f"{job_name}-{index}")] = script
        with tempfile.NamedTemporaryFile("w", suffix=".sh", encoding="utf-8") as handle:
            handle.write(script)
            handle.flush()
            result = checked(["bash", "-n", handle.name])
        require_success(result, f"Bash syntax in {job_name}/{step.get('name', index)}")

expected_actions = {
    "actions/checkout": ("11bd71901bbe5b1630ceea73d27597364c9af683", "v4.2.2", 7),
    "actions/setup-go": ("d35c59abb061a4a6fb18e82ac0862c26744d6ab5", "v5.5.0", 4),
    "actions/setup-node": ("49933ea5288caeca8642d1e84afbd3f7d6820020", "v4.4.0", 2),
    "actions/upload-artifact": ("ea165f8d65b6e75b540449e92b4886f43607fa02", "v4.6.2", 3),
    "actions/download-artifact": ("d3f86a106a0bac45b974a628896c90dbdf5c8093", "v4.3.0", 4),
}
counts = {name: 0 for name in expected_actions}
for job_name, step in actions:
    action = step["uses"]
    match = re.fullmatch(r"(actions/[a-z-]+)@([0-9a-f]{40})", action or "")
    if not match or match.group(1) not in expected_actions:
        raise SystemExit(f"unapproved or non-SHA-pinned action in {job_name}: {action}")
    name, sha = match.groups()
    expected_sha, _, _ = expected_actions[name]
    if sha != expected_sha:
        raise SystemExit(f"{name} SHA is {sha}, want verified {expected_sha}")
    counts[name] += 1
for name, (_, version, expected_count) in expected_actions.items():
    if counts[name] != expected_count:
        raise SystemExit(f"{name} occurs {counts[name]} times, want {expected_count}")
    sha = expected_actions[name][0]
    comment_pattern = rf"uses:\s*{re.escape(name)}@{sha}\s+#\s*{re.escape(version)}\s*$"
    if not re.search(comment_pattern, workflow_text, re.MULTILINE):
        raise SystemExit(f"{name} pin is missing its {version} audit comment")


def step_named(steps, name):
    matches = [step for step in steps if step.get("name") == name]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one step named {name!r}")
    return matches[0]


for job_name, steps in (
    ("build_windows", windows_steps),
    ("build_linux", linux_steps),
    ("accept_linux", accept_steps),
    ("sign_publish", sign_steps),
):
    checkouts = [step for step in steps if str(step.get("uses", "")).startswith("actions/checkout@")]
    for checkout in checkouts:
        if checkout.get("with", {}).get("persist-credentials") != "false":
            raise SystemExit(f"{job_name} checkout must set persist-credentials: false")

for job_name, steps in (("build_windows", windows_steps), ("build_linux", linux_steps)):
    private_checkout = step_named(steps, "Check out the private source at the validated tag")
    if private_checkout.get("with") != {
        "repository": "julubileu/jayflow-v2",
        "ref": "${{ steps.inputs.outputs.ref }}",
        "ssh-key": "${{ secrets.JAYFLOW_SOURCE_DEPLOY_KEY }}",
        "path": "source",
        "persist-credentials": "false",
    }:
        raise SystemExit(f"{job_name} private checkout is not exact-tag/read-only-key scoped")
accept_private_checkout = step_named(accept_steps, "Check out the private source from the Linux build")
if accept_private_checkout.get("with") != {
    "repository": "julubileu/jayflow-v2",
    "ref": "${{ needs.build_linux.outputs.ref }}",
    "ssh-key": "${{ secrets.JAYFLOW_SOURCE_DEPLOY_KEY }}",
    "path": "source",
    "persist-credentials": "false",
}:
    raise SystemExit("accept_linux must check out exactly the build_linux resolved ref")
for job_name, steps in (
    ("build_windows", windows_steps),
    ("build_linux", linux_steps),
    ("accept_linux", accept_steps),
):
    secret_steps = [step for step in steps if "JAYFLOW_SOURCE_DEPLOY_KEY" in serialized(step)]
    if len(secret_steps) != 1 or "ssh-key" not in secret_steps[0].get("with", {}):
        raise SystemExit(f"{job_name} deploy key must appear only on its private checkout")

public_sign_checkout = step_named(sign_steps, "Check out only the public release repository")
if "repository" in public_sign_checkout.get("with", {}):
    raise SystemExit("sign_publish checkout must only check out this public repository")
for job_name, steps in (("build_windows", windows_steps), ("build_linux", linux_steps)):
    public_auditor_build = step_named(steps, "Build the trusted public auditor")
    if public_auditor_build.get("working-directory") != "release":
        raise SystemExit(f"{job_name} must compile the nested public Go module from working-directory release")
source_info_template = source_repo / "cmd" / "jayflow" / "build" / "windows" / "info.json"
if not source_info_template.is_file():
    raise SystemExit("private source Windows info.json template is missing")
if '"Comments": "{{.Info.Comments}}"' not in source_info_template.read_text(encoding="utf-8"):
    raise SystemExit("private source Windows info.json does not expose Wails comments")

for job_name, job in (("build_windows", build_windows), ("build_linux", build_linux)):
    if job.get("outputs") != {
        "version": "${{ steps.inputs.outputs.version }}",
        "ref": "${{ steps.inputs.outputs.ref }}",
        "source_sha": "${{ steps.source.outputs.sha }}",
    }:
        raise SystemExit(f"{job_name} outputs must come only from its resolved tag checkout")

upload = step_named(windows_steps, "Upload the unsigned Windows internal artifact")
download = step_named(sign_steps, "Download the unsigned Windows internal artifact")
if upload.get("with", {}).get("name") != "unsigned-windows-release-assets":
    raise SystemExit("Windows build artifact has wrong name")
if upload.get("with", {}).get("path") != "source/dist-windows/":
    raise SystemExit("Windows assets must be isolated in source/dist-windows/")
if upload.get("with", {}).get("if-no-files-found") != "error":
    raise SystemExit("Windows artifact upload must fail when outputs are absent")
if download.get("with", {}).get("name") != "unsigned-windows-release-assets":
    raise SystemExit("sign_publish does not download the exact Windows artifact")
if download.get("with", {}).get("path") != "dist":
    raise SystemExit("sign_publish must download Windows assets to dist/")
daemon_upload = step_named(windows_steps, "Upload the separately audited daemon artifact")
daemon_download = step_named(sign_steps, "Download the separate audited daemon artifact")
if daemon_upload.get("with", {}).get("name") != "audited-embedded-daemon":
    raise SystemExit("daemon artifact is not separate from unsigned dist")
if daemon_upload.get("with", {}).get("path") != "source/cmd/jayflow/embedded/jayflowd":
    raise SystemExit("daemon artifact path is not the exact audited ELF")
if daemon_upload.get("with", {}).get("if-no-files-found") != "error":
    raise SystemExit("daemon artifact upload must fail when the ELF is absent")
if daemon_download.get("with", {}).get("name") != "audited-embedded-daemon":
    raise SystemExit("sign_publish does not download the separate daemon artifact")
if daemon_download.get("with", {}).get("path") != "internal-daemon":
    raise SystemExit("daemon artifact must stay outside dist")

linux_upload = step_named(linux_steps, "Upload the unsigned Linux gateway")
accept_download = step_named(accept_steps, "Download the transported Linux gateway")
sign_linux_download = step_named(sign_steps, "Download the unsigned Linux gateway")
if linux_upload.get("with", {}).get("name") != "unsigned-linux-gateway":
    raise SystemExit("Linux artifact has wrong name")
if linux_upload.get("with", {}).get("path") != "source/dist-linux/jayflow-web-${{ steps.inputs.outputs.version }}-linux-amd64":
    raise SystemExit("Linux upload path must be the exact isolated gateway")
for download_step, destination in ((accept_download, "candidate"), (sign_linux_download, "linux-dist")):
    if download_step.get("with", {}).get("name") != "unsigned-linux-gateway":
        raise SystemExit("Linux consumer downloads the wrong internal artifact")
    if download_step.get("with", {}).get("path") != destination:
        raise SystemExit(f"Linux artifact must download to {destination}/")

for name, upload_step in (
    ("Windows", upload),
    ("daemon", daemon_upload),
    ("Linux", linux_upload),
):
    config = upload_step.get("with", {})
    if config.get("if-no-files-found") != "error" or config.get("retention-days") != "1" or config.get("compression-level") != "0":
        raise SystemExit(f"{name} upload must use error/retention 1/compression 0")

if "dist-linux" in serialized(windows_steps) or "dist-windows" in serialized(linux_steps):
    raise SystemExit("Windows and Linux build destinations must remain isolated")
if "internal-daemon" in serialized(windows_steps) or "candidate/" in serialized(sign_steps):
    raise SystemExit("internal artifact trust boundaries are mixed")
public_dist = re.compile(r"(?<![\w./-])dist/")
for step in sign_steps:
    for line in str(step.get("run", "")).splitlines():
        if "internal-daemon" in line and public_dist.search(line):
            raise SystemExit(f"the audited embedded daemon must never enter the public dist tree: {line.strip()}")

for secret_step_name in (
    "Derive and verify the release public key",
    "Sign final bytes and generate authenticated metadata",
):
    secret_step = step_named(sign_steps, secret_step_name)
    if secret_step.get("env", {}).get("JAYFLOW_RELEASE_PRIVATE_KEY") != "${{ secrets.JAYFLOW_RELEASE_PRIVATE_KEY }}":
        raise SystemExit(f"{secret_step_name} does not receive the signing secret exactly")
    secret_script = secret_step["run"]
    for forbidden in ("go run", "source/", "jayflow-v2", "npm ", "go test"):
        if forbidden in secret_script:
            raise SystemExit(f"secret-bearing step executes forbidden source/tooling text: {forbidden}")
    if '"$RUNNER_TEMP/jayflow-release-tool"' not in secret_script:
        raise SystemExit("secret-bearing step does not exclusively use the compiled public tool")
    for occurrence in re.finditer("JAYFLOW_RELEASE_PRIVATE_KEY", secret_script):
        if secret_script[max(0, occurrence.start() - 2):occurrence.start()] != "${":
            raise SystemExit(f"{secret_step_name} must read the signing key from the environment, never argv")
secret_bearing_steps = [
    step for step in sign_steps
    if step.get("env", {}).get("JAYFLOW_RELEASE_PRIVATE_KEY") == "${{ secrets.JAYFLOW_RELEASE_PRIVATE_KEY }}"
]
if [step.get("name") for step in secret_bearing_steps] != [
    "Derive and verify the release public key",
    "Sign final bytes and generate authenticated metadata",
]:
    raise SystemExit("private signing key must be scoped to exactly the two minimal final steps")

last_download_index = max(
    index for index, step in enumerate(sign_steps)
    if str(step.get("uses", "")).startswith("actions/download-artifact@")
)
first_executable_after_downloads = next(
    step for step in sign_steps[last_download_index + 1:] if "run" in step
)
if first_executable_after_downloads.get("name") != "Reconcile independent build identities":
    raise SystemExit("build identity reconciliation must be the first executable step after downloads")
reconcile = first_executable_after_downloads
if reconcile.get("env") != {
    "WINDOWS_VERSION": "${{ needs.build_windows.outputs.version }}",
    "LINUX_VERSION": "${{ needs.build_linux.outputs.version }}",
    "WINDOWS_REF": "${{ needs.build_windows.outputs.ref }}",
    "LINUX_REF": "${{ needs.build_linux.outputs.ref }}",
    "WINDOWS_SHA": "${{ needs.build_windows.outputs.source_sha }}",
    "LINUX_SHA": "${{ needs.build_linux.outputs.source_sha }}",
}:
    raise SystemExit("sign_publish identity reconciliation is not tied to both resolved builds")
for exact in (
    '[ "$WINDOWS_VERSION" = "$LINUX_VERSION" ] || { echo "::error::build versions differ"; exit 1; }',
    '[ "$WINDOWS_REF" = "$LINUX_REF" ] || { echo "::error::build refs differ"; exit 1; }',
    '[ "$WINDOWS_SHA" = "$LINUX_SHA" ] || { echo "::error::build source SHAs differ"; exit 1; }',
):
    if exact not in reconcile["run"]:
        raise SystemExit(f"identity reconciliation is missing exact gate: {exact}")

for job_name, steps in (("build_windows", windows_steps), ("build_linux", linux_steps)):
    identity = step_named(steps, "Record and verify source identity")["run"]
    for required in (
        'SOURCE_SHA="$(git rev-parse HEAD)"',
        'TAG_SHA="$(git rev-parse --verify "refs/tags/${SOURCE_REF}^{commit}")"',
        "git diff --exit-code",
        "git ls-files --others --exclude-standard",
        "git status --porcelain --untracked-files=all",
    ):
        if required not in identity:
            raise SystemExit(f"{job_name} source identity permits dirty/unresolved checkout: {required}")

accept_identity = step_named(accept_steps, "Verify accepted source identity")
if accept_identity.get("env") != {
    "EXPECTED_REF": "${{ needs.build_linux.outputs.ref }}",
    "EXPECTED_SHA": "${{ needs.build_linux.outputs.source_sha }}",
}:
    raise SystemExit("accept_linux source verification is not bound to build_linux outputs")
for required in ('git rev-parse HEAD', 'refs/tags/${EXPECTED_REF}^{commit}', 'git diff --exit-code', 'git ls-files --others --exclude-standard', 'git status --porcelain --untracked-files=all'):
    if required not in accept_identity["run"]:
        raise SystemExit(f"accept_linux source identity is missing {required}")

input_script = scripts["Validate release inputs"]
safe_env = {
    key: os.environ[key]
    for key in (
        "PATH", "HOME", "USER", "LANG", "GOPATH", "GOMODCACHE", "GOCACHE",
        "GOENV", "TMPDIR", "XDG_CACHE_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    )
    if key in os.environ
}
safe_env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
safe_env["LANG"] = "C.UTF-8"
input_cases = [
    ("0.0.0", "v0.0.0", True),
    ("2.0.33", "v2.0.33", True),
    ("2.0.33-dev", "v2.0.33-dev", True),
    ("65535.65535.65535", "v65535.65535.65535", True),
    ("65536.1.1", "v65536.1.1", False),
    ("18446744073709551616.1.1", "v18446744073709551616.1.1", False),
    ("1.65536.1", "v1.65536.1", False),
    ("1.1.65536-dev", "v1.1.65536-dev", False),
    ("01.2.3", "v01.2.3", False),
    ("1.02.3", "v1.02.3", False),
    ("1.2.03", "v1.2.03", False),
    ("1.2.3-rc1", "v1.2.3-rc1", False),
    ("1.2.3+build", "v1.2.3+build", False),
    ("2.0.33", "refs/tags/v2.0.33", False),
    ("2.0.33", "0123456789abcdef0123456789abcdef01234567", False),
    ("2.0.33", "main", False),
    ("2.0.33", "v2.0.34", False),
    ("2.0.33", "v2.0.33\necho-pwn", False),
]
with tempfile.NamedTemporaryFile("w", suffix=".sh", encoding="utf-8") as script_file:
    script_file.write(input_script)
    script_file.flush()
    for version, ref, should_pass in input_cases:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as output_file:
            env = safe_env.copy()
            env.update({"INPUT_VERSION": version, "INPUT_REF": ref, "GITHUB_OUTPUT": output_file.name})
            result = checked(["bash", script_file.name], env=env)
            if (result.returncode == 0) != should_pass:
                expectation = "pass" if should_pass else "fail"
                raise SystemExit(f"input validation should {expectation} for version={version!r}, ref={ref!r}")
            if should_pass:
                got = pathlib.Path(output_file.name).read_text(encoding="utf-8")
                if got != f"version={version}\nref=v{version}\n":
                    raise SystemExit(f"input validation outputs differ for {version}")

epoch_script = scripts["Derive the reproducible source epoch"]
for required in (
    'SOURCE_SHA="$(git rev-parse HEAD)"',
    'SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$SOURCE_SHA")"',
    'SOURCE_DATE_EPOCH=%s\\n',
    '"$GITHUB_ENV"',
):
    if required not in epoch_script:
        raise SystemExit(f"source epoch is not commit-derived/exported: {required}")

stamp_script = scripts["Build the stamped Windows app and NSIS installer twice"]
stamp_step = step_named(windows_steps, "Build the stamped Windows app and NSIS installer twice")
if stamp_step.get("env", {}).get("SOURCE_SHA") != "${{ steps.source.outputs.sha }}":
    raise SystemExit("Windows build SOURCE_SHA is not tied to the validated source step")
stamp_prefix, marker, build_suffix = stamp_script.partition("\nbuild_windows_app()")
if not marker:
    raise SystemExit("Windows build step does not define the reproducible app build function")
with tempfile.TemporaryDirectory() as temp_dir:
    config = pathlib.Path(temp_dir, "wails.json")
    config.write_text(
        '{"name":"jayflow","info":{"productName":"JayFlow","productVersion":"2.0.0-dev",'
        '"comments":"untrusted source comment"}}\n',
        encoding="utf-8",
    )
    env = safe_env.copy()
    env.update({
        "VERSION": "2.0.33-dev",
        "SOURCE_SHA": "0123456789abcdef0123456789abcdef01234567",
        "PUBLIC_KEY": "test-public-key",
    })
    for invalid_sha in (
        "0123456789abcdef",
        "0123456789ABCDEF0123456789ABCDEF01234567",
        "g123456789abcdef0123456789abcdef01234567",
    ):
        env["SOURCE_SHA"] = invalid_sha
        result = checked(["bash", "-c", stamp_prefix], cwd=temp_dir, env=env)
        if result.returncode == 0:
            raise SystemExit(f"Wails metadata stamp accepted invalid source SHA {invalid_sha!r}")
    env["SOURCE_SHA"] = "0123456789abcdef0123456789abcdef01234567"
    result = checked(["bash", "-c", stamp_prefix], cwd=temp_dir, env=env)
    require_success(result, "Wails metadata stamping")
    stamped = json.loads(config.read_text(encoding="utf-8"))
    if stamped["info"]["productVersion"] != "2.0.33":
        raise SystemExit("Wails productVersion must be numeric X.Y.Z")
    if stamped["info"].get("comments") != "source_sha=0123456789abcdef0123456789abcdef01234567":
        raise SystemExit("Wails comments must overwrite source metadata with the validated SHA marker")
comments_assignment = 'config.info.comments = `source_sha=${sourceSHA}`;'
if comments_assignment not in stamp_prefix:
    raise SystemExit("Windows metadata stamp does not assign the exact source SHA comments marker")
first_stamp_call = stamp_script.index("\nstamp_windows_metadata\n")
if stamp_script.index(comments_assignment) > first_stamp_call:
    raise SystemExit("Wails comments source marker must be assigned before the first Wails build")
if "wails build" not in build_suffix:
    raise SystemExit("Windows build step does not invoke Wails")
if 'wails build "$@"' not in build_suffix:
    raise SystemExit("Windows app build function does not forward the one audited -nsis flag")
if '-X main.DaemonVersion=${VERSION} -X main.AppVersion=${VERSION}' not in build_suffix:
    raise SystemExit("Windows build does not stamp both full AppVersion and DaemonVersion")
if "PublicKeyBase64=${PUBLIC_KEY}" not in build_suffix:
    raise SystemExit("Windows build does not stamp the public release key")
for required in ("-platform windows/amd64", "-nsis", "-installscope user", "-trimpath"):
    if required not in build_suffix:
        raise SystemExit(f"Windows Wails build is missing {required}")
for required in (
    'FIRST_BUILD_DIR="$RUNNER_TEMP/first-windows-build"',
    'NSIS_PROJECT="build/windows/installer/project.nsi"',
    'NSIS_TOOLS="build/windows/installer/wails_tools.nsh"',
    'NSIS_BOOTSTRAPPER="build/windows/installer/tmp/MicrosoftEdgeWebview2Setup.exe"',
    "mapfile -d '' -t NSIS_OUTPUTS",
    "find build/bin -maxdepth 1 -type f -name '*-amd64-installer.exe' -print0",
    'if [ "${#NSIS_OUTPUTS[@]}" -ne 1 ]; then',
    'NSIS_OUTPUT="${NSIS_OUTPUTS[0]}"',
    "stamp_windows_metadata",
    "build_windows_app",
    "make_nsis",
    "SetDateSave off",
    'sed -i \'1a SetDateSave off\' "$NSIS_PROJECT"',
    "wails_tools.nsh must not override the project SetDateSave policy",
    "git restore --worktree -- wails.json frontend/wailsjs/go/models.ts",
    "rm -rf -- build/bin",
    'cmp -s "$FIRST_BUILD_DIR/JayFlow.exe" build/bin/JayFlow.exe',
    'cmp -s "$FIRST_BUILD_DIR/installer.exe" "$NSIS_OUTPUT"',
):
    if required not in stamp_script:
        raise SystemExit(f"Windows reproducibility proof is missing {required}")
if re.search(r'build/bin/[^\s"\']*-amd64-installer\.exe', stamp_script):
    raise SystemExit("Windows NSIS output must be discovered without hardcoded project-name casing")
if stamp_script.count("-name '*-amd64-installer.exe'") != 1:
    raise SystemExit("Windows NSIS output must use exactly one case-sensitive filename search")
if re.search(r'find[^\n]*[ \t]-iname(?:[ \t]|$)', stamp_script):
    raise SystemExit("Windows NSIS output discovery must not use case-insensitive matching")
if len(re.findall(r"^build_windows_app(?: -nsis)?$", stamp_script, re.MULTILINE)) != 2:
    raise SystemExit("Windows app must be built exactly twice")
if len(re.findall(r"^build_windows_app -nsis$", stamp_script, re.MULTILINE)) != 1:
    raise SystemExit("Wails must generate the NSIS project exactly once")
if len(re.findall(r"^make_nsis$", stamp_script, re.MULTILINE)) != 2:
    raise SystemExit("makensis must build the canonical installer exactly twice")
if len(re.findall(r"^[ \t]*makensis \\$", stamp_script, re.MULTILINE)) != 1:
    raise SystemExit("manual makensis must be defined exactly once")
if stamp_script.count("-DARG_WAILS_AMD64_BINARY=../../bin/JayFlow.exe") != 1:
    raise SystemExit("manual makensis must use the exact Wails amd64 binary define")
if stamp_script.count("-DWAILS_INSTALL_SCOPE=user") != 1:
    raise SystemExit("manual makensis must use the exact Wails user-scope define")
if stamp_script.count("-DREQUEST_EXECUTION_LEVEL=user") != 1:
    raise SystemExit("manual makensis must use the exact Wails execution-level define")
if "touch " in stamp_script or "SOURCE_DATE_EPOCH=" in stamp_script:
    raise SystemExit("Windows build must not normalize mtimes or replace the commit-derived epoch")
if len(re.findall(r"^stamp_windows_metadata$", stamp_script, re.MULTILINE)) != 2:
    raise SystemExit("both Windows builds must start from the same metadata stamp")
first_build = stamp_script.index("\nbuild_windows_app -nsis\n")
discover_output = stamp_script.index("mapfile -d '' -t NSIS_OUTPUTS")
select_output = stamp_script.index('NSIS_OUTPUT="${NSIS_OUTPUTS[0]}"')
date_save = stamp_script.index("sed -i '1a SetDateSave off'")
first_makensis = stamp_script.index("\nmake_nsis\n")
preserve_first = stamp_script.index('cp "$NSIS_OUTPUT" "$FIRST_BUILD_DIR/installer.exe"')
restore = stamp_script.index("git restore --worktree -- wails.json frontend/wailsjs/go/models.ts")
second_stamp = stamp_script.rindex("\nstamp_windows_metadata\n")
second_build = stamp_script.rindex("\nbuild_windows_app\n")
second_makensis = stamp_script.rindex("\nmake_nsis\n")
compare_app = stamp_script.index('cmp -s "$FIRST_BUILD_DIR/JayFlow.exe" build/bin/JayFlow.exe')
compare_installer = stamp_script.index('cmp -s "$FIRST_BUILD_DIR/installer.exe" "$NSIS_OUTPUT"')
if not (
    first_stamp_call < first_build < discover_output < select_output < date_save < first_makensis < preserve_first < restore < second_stamp
    < second_build < second_makensis < compare_app < compare_installer
):
    raise SystemExit("Windows app/NSIS generation, preservation, and comparison order is wrong")

with tempfile.TemporaryDirectory() as temp_dir_text:
    temp_dir = pathlib.Path(temp_dir_text)
    project_dir = temp_dir / "source" / "cmd" / "jayflow"
    project_dir.mkdir(parents=True)
    (project_dir / "frontend" / "wailsjs" / "go").mkdir(parents=True)
    (project_dir / "frontend" / "wailsjs" / "go" / "models.ts").write_text(
        "fixture\n", encoding="utf-8"
    )
    (project_dir / "wails.json").write_text(
        '{"name":"jayflow","info":{"productName":"JayFlow","productVersion":"2.0.0-dev",'
        '"comments":"untrusted source comment"}}\n',
        encoding="utf-8",
    )
    fake_bin = temp_dir / "fake-bin"
    fake_bin.mkdir()
    call_log = temp_dir / "calls.jsonl"

    fake_wails = fake_bin / "wails"
    fake_wails.write_text(r'''#!/usr/bin/env python3
import json
import os
import pathlib
import sys

root = pathlib.Path.cwd()
with pathlib.Path(os.environ["FAKE_BUILD_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "tool": "wails",
        "args": sys.argv[1:],
        "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH"),
        "source_marker": json.loads((root / "wails.json").read_text(encoding="utf-8"))["info"].get("comments"),
    }) + "\n")
count_file = pathlib.Path(os.environ["FAKE_WAILS_COUNT"])
count = int(count_file.read_text(encoding="utf-8")) + 1 if count_file.exists() else 1
count_file.write_text(str(count), encoding="utf-8")
binary = root / "build" / "bin" / "JayFlow.exe"
binary.parent.mkdir(parents=True, exist_ok=True)
binary.write_bytes(b"identical JayFlow app bytes\n")
mtime = 1700000000 + count
os.utime(binary, (mtime, mtime))
if "-nsis" in sys.argv[1:]:
    project_name = json.loads((root / "wails.json").read_text(encoding="utf-8"))["name"]
    installer = root / "build" / "windows" / "installer"
    (installer / "tmp").mkdir(parents=True, exist_ok=True)
    (installer / "project.nsi").write_text(
        'Unicode true\n\n!include "wails_tools.nsh"\n'
        'Section\n  !insertmacro wails.webview2runtime\n'
        '  !insertmacro wails.files\nSectionEnd\n',
        encoding="utf-8",
    )
    (installer / "wails_tools.nsh").write_text(
        '!macro wails.files\n'
        '  File "/oname=${PRODUCT_EXECUTABLE}" "${ARG_WAILS_AMD64_BINARY}"\n'
        '!macroend\n'
        '!macro wails.webview2runtime\n'
        '  File "tmp\\MicrosoftEdgeWebview2Setup.exe"\n'
        '!macroend\n',
        encoding="utf-8",
    )
    (installer / "tmp" / "MicrosoftEdgeWebview2Setup.exe").write_bytes(
        b"webview bootstrapper bytes\n"
    )
    output_count = int(os.environ.get("FAKE_WAILS_INSTALLER_COUNT", "1"))
    for index in range(output_count):
        output_name = (
            f"{project_name}-amd64-installer.exe"
            if index == 0
            else f"extra-{index}-amd64-installer.exe"
        )
        (root / "build" / "bin" / output_name).write_bytes(
            b"automatic Wails installer must be discarded\n"
        )
''', encoding="utf-8")
    fake_wails.chmod(0o755)

    fake_makensis = fake_bin / "makensis"
    fake_makensis.write_text(r'''#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import sys

args = sys.argv[1:]
with pathlib.Path(os.environ["FAKE_BUILD_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({
        "tool": "makensis",
        "args": args,
        "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH"),
    }) + "\n")
expected = [
    "-DARG_WAILS_AMD64_BINARY=../../bin/JayFlow.exe",
    "-DWAILS_INSTALL_SCOPE=user",
    "-DREQUEST_EXECUTION_LEVEL=user",
    "project.nsi",
]
if args != expected:
    raise SystemExit(f"unexpected makensis arguments: {args!r}")
project = pathlib.Path("project.nsi")
lines = project.read_text(encoding="utf-8").splitlines()
if lines.count("SetDateSave off") != 1:
    raise SystemExit("SetDateSave off must be an exact unique line")
if lines[1] != "SetDateSave off":
    raise SystemExit("SetDateSave off must be exact line 2")
if lines.index("SetDateSave off") >= lines.index('!include "wails_tools.nsh"'):
    raise SystemExit("SetDateSave off must precede the Wails File macros")
tools = pathlib.Path("wails_tools.nsh").read_text(encoding="utf-8")
for required_file in (
    'File "/oname=${PRODUCT_EXECUTABLE}" "${ARG_WAILS_AMD64_BINARY}"',
    'File "tmp\\MicrosoftEdgeWebview2Setup.exe"',
):
    if required_file not in tools:
        raise SystemExit(f"missing relevant NSIS File input: {required_file}")
binary = pathlib.Path("../../bin/JayFlow.exe")
body = binary.read_bytes()
digest = hashlib.sha256(b"manual-nsis\0" + body).digest()
project_root = pathlib.Path.cwd().parents[2]
project_name = json.loads((project_root / "wails.json").read_text(encoding="utf-8"))["name"]
(project_root / "build" / "bin" / f"{project_name}-amd64-installer.exe").write_bytes(digest)
''', encoding="utf-8")
    fake_makensis.chmod(0o755)

    fake_git = fake_bin / "git"
    fake_git.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    fake_git.chmod(0o755)

    env = safe_env.copy()
    env.update({
        "PATH": f"{fake_bin}:{safe_env['PATH']}",
        "VERSION": "2.0.33-dev",
        "SOURCE_SHA": "0123456789abcdef0123456789abcdef01234567",
        "PUBLIC_KEY": "test-public-key",
        "RUNNER_TEMP": str(temp_dir / "runner-temp"),
        "SOURCE_DATE_EPOCH": "1700000000",
        "FAKE_BUILD_LOG": str(call_log),
        "FAKE_WAILS_COUNT": str(temp_dir / "wails-count"),
    })
    pathlib.Path(env["RUNNER_TEMP"]).mkdir()
    for installer_count in ("0", "2"):
        env["FAKE_WAILS_INSTALLER_COUNT"] = installer_count
        result = checked(["bash", "-c", stamp_script], cwd=project_dir, env=env)
        if result.returncode == 0:
            raise SystemExit(
                f"behavioral workflow accepted {installer_count} Wails installer candidates"
            )
        if "must produce exactly one disposable amd64 installer" not in (result.stdout + result.stderr):
            raise SystemExit(
                f"behavioral workflow failed incorrectly for {installer_count} installer candidates"
            )
        shutil.rmtree(project_dir / "build", ignore_errors=True)
        shutil.rmtree(pathlib.Path(env["RUNNER_TEMP"]) / "first-windows-build")
        call_log.unlink()
        pathlib.Path(env["FAKE_WAILS_COUNT"]).unlink()
    env["FAKE_WAILS_INSTALLER_COUNT"] = "1"
    result = checked(["bash", "-c", stamp_script], cwd=project_dir, env=env)
    require_success(result, "behavioral Windows/NSIS reproducibility workflow")

    calls = [
        json.loads(line)
        for line in call_log.read_text(encoding="utf-8").splitlines()
    ]
    wails_calls = [call for call in calls if call["tool"] == "wails"]
    makensis_calls = [call for call in calls if call["tool"] == "makensis"]
    if len(wails_calls) != 2 or "-nsis" not in wails_calls[0]["args"]:
        raise SystemExit("behavioral workflow must use the first Wails build to generate NSIS")
    if "-nsis" in wails_calls[1]["args"]:
        raise SystemExit("second Wails build must not overwrite the generated NSIS project")
    if [arg for arg in wails_calls[0]["args"] if arg != "-nsis"] != wails_calls[1]["args"]:
        raise SystemExit("both Wails app builds must use identical arguments except for first-build -nsis")
    if any(call["source_date_epoch"] != "1700000000" for call in wails_calls):
        raise SystemExit("SOURCE_DATE_EPOCH did not reach both Wails app builds")
    if any(call["source_marker"] != "source_sha=0123456789abcdef0123456789abcdef01234567" for call in wails_calls):
        raise SystemExit("validated source marker did not reach both Wails app builds")
    if len(makensis_calls) != 2:
        raise SystemExit("behavioral workflow did not execute manual makensis twice")
    if any(call["source_date_epoch"] != "1700000000" for call in makensis_calls):
        raise SystemExit("SOURCE_DATE_EPOCH did not reach both manual makensis builds")
    first_installer = pathlib.Path(env["RUNNER_TEMP"]) / "first-windows-build" / "installer.exe"
    second_installers = list((project_dir / "build" / "bin").glob("*-amd64-installer.exe"))
    if len(second_installers) != 1:
        raise SystemExit("behavioral workflow did not leave exactly one amd64 installer")
    second_installer = second_installers[0]
    if first_installer.read_bytes() != second_installer.read_bytes():
        raise SystemExit("behavioral workflow did not preserve/compare reproducible manual installers")
    if first_installer.read_bytes() == b"automatic Wails installer must be discarded\n":
        raise SystemExit("automatic Wails installer was preserved instead of the manual canonical output")

nsis_audit = scripts["Audit pinned Wails NSIS user-scope semantics"]
for required in (
    "-DARG_WAILS_AMD64_BINARY=",
    "-DWAILS_INSTALL_SCOPE=user",
    "-DREQUEST_EXECUTION_LEVEL=user",
    '$LOCALAPPDATA\\Programs\\${INFO_PRODUCTNAME}',
    'VIProductVersion "${INFO_PRODUCTVERSION}.0"',
    'VIFileVersion    "${INFO_PRODUCTVERSION}.0"',
):
    if required not in nsis_audit:
        raise SystemExit(f"pinned NSIS semantic audit is missing {required}")

daemon_script = scripts["Build and audit the embedded Linux daemon"]
for required in (
    "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath",
    "-X main.Version=${VERSION}",
    "audit-daemon",
):
    if required not in daemon_script:
        raise SystemExit(f"daemon build/audit is missing {required}")

linux_gate_script = scripts["Run focused Linux release gates"]
for required in (
    "go test -race ./internal/updater ./internal/webservice ./internal/gateway ./internal/webserver ./cmd/jayflow-web -count=1",
    "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go vet ./cmd/jayflow-web ./internal/updater ./internal/webservice ./internal/gateway ./internal/webserver",
    "git diff --check",
    "git diff --exit-code",
):
    if required not in linux_gate_script:
        raise SystemExit(f"focused Linux gates are missing {required}")

# ─── the private source gate environment (strace 7.1, gate root, userns) ─────
#
# The private gates are fail-closed by design: they require an absolute
# JAYFLOW_LOCAL_GATE_ROOT holding a tasks/ directory, the exact strace 7.1
# whose syscall table the spec pinned, x86_64, and a real unprivileged
# CLONE_NEWUSER. The runner image supplies none of the three, so one identical
# preparation step must establish all of them before any gate runs, and only
# the gate steps may receive the resulting environment.

STRACE_URL = "https://github.com/strace/strace/releases/download/v7.1/strace-7.1.tar.xz"
STRACE_SHA256 = "81743ecf2a5b44186b2f5038afdc8beda7e5c70aed15b4fbfbcc6e9ece24490f"
STRACE_VERSION_LINE = "strace -- version 7.1"
# The gate scratch has four measured requirements, and only a fresh tmpfs
# mounted over the runner's own /tmp satisfies all four at once:
#   (A) the gates refuse a gate root or a validated scratch inside the account's
#       real home, and RUNNER_TEMP is /home/runner/work/_temp on the runner;
#   (B) the ext4 backing the runner's /tmp recycles inode numbers immediately,
#       so the identity races observe a replacement wearing the identity they
#       had just probed. tmpfs draws inode numbers from a monotonic counter,
#       which is the reference machine's behaviour these gates were designed
#       against;
#   (C) the kernel caps a Unix socket path at 107 bytes. Measured on the runner,
#       the deepest gate socket was 122 bytes under /dev/shm/jayflow-tmp and bind
#       refused it across 28 tests in cmd/jayflow-web, cmd/jayflowd,
#       internal/mobileprov, internal/securepath and internal/webserver. The very
#       same socket is 106 bytes under /tmp, which is why the reference machine
#       never saw the failure. The scratch prefix therefore has a byte budget;
#   (D) cmd/jayflowd/fsbroker_linux_test.go opens one fixture on t.TempDir() and
#       one on /dev/shm and fails when the two report the same device, so the
#       scratch must be a filesystem of its own, distinct from /dev/shm.
# The reference machine is exactly that shape: /tmp is its own tmpfs and
# /dev/shm is another. Mounting a bounded tmpfs over /tmp reproduces it.
GATE_TMPFS = "/tmp"
GATE_TMPFS_OPTIONS = "size=4g,mode=1777,nosuid,nodev"
GATE_FOREIGN_TMPFS = "/dev/shm"
GATE_ROOT_EXPRESSION = "/tmp/jayflow-gate"
GATE_TMPDIR_EXPRESSION = "/tmp"
# The kernel's sun_path budget, and the longest suffix the gates were measured to
# append to their own TMPDIR (122 observed bytes behind a 20-byte prefix).
UNIX_SOCKET_PATH_LIMIT = 107
MEASURED_GATE_SOCKET_SUFFIX = 102
# "/tmp" as a path of its own, so an unrelated "installer/tmp/" never counts as
# a step naming the gate scratch.
GATE_TMPFS_PATTERN = re.compile(r"(?<![\w./-])" + re.escape(GATE_TMPFS) + r"(?![\w-])")


def names_gate_tmpfs(text):
    return GATE_TMPFS_PATTERN.search(text) is not None


# The failure-only diagnostics step in accept_linux has to name /tmp and
# /dev/shm: their mode and their filesystem are two of the four facts that
# separate "the runner's /home refuses the disposable home" from "the user
# manager never got a /run/user". That is a read of the runner's layout, not a
# provisioning of a gate scratch, so it is scoped down to these two exact lines
# instead of being forbidden outright: everywhere else in the job, naming either
# path still means the gate environment leaked in.
ACCEPT_DIAGNOSTICS_STEP_NAME = "Collect acceptance diagnostics"
# On the hosted image /home/runner is 0750 runner:runner, so the disposable
# jfrelNNNN user the harness creates cannot traverse it. Every input the harness
# is handed has to be reachable BY THAT USER: the daemon named in the fixture
# unit's ExecStart, the Playwright script started with `runuser -u jfrelNNNN`,
# and the playwright-core package node resolves beside it. The disposable VM
# where this harness passed 8/8 kept all of them under /opt with a+rX; this is
# that layout, reproduced on the runner. A path under the home is not a weaker
# acceptance, it is an EACCES the harness can only report as "the daemon fixture
# did not become active".
ACCEPT_STAGE_STEP_NAME = "Stage the acceptance inputs outside the runner home"
ACCEPTANCE_ROOT = "/opt/jayflow-acceptance"
ACCEPT_DIAGNOSTICS_LAYOUT_LINES = (
    "stat -c '%a %U:%G %n' /home /run/user /tmp /dev/shm",
    "mount | grep -E '/home|/tmp|/dev/shm|/run/user'",
)


def without_diagnostics_layout(text):
    for line in ACCEPT_DIAGNOSTICS_LAYOUT_LINES:
        text = text.replace(line, "")
    return text


# 2 GiB. One focused gate run holds the Go build work directories, the traced
# gateway instances and the SQLite scratch under TMPDIR at the same time, and a
# tmpfs is charged against the runner's RAM. Below that floor the run dies of
# ENOSPC inside a gate, which is indistinguishable from a real gate failure;
# refusing here names what actually happened.
GATE_TMPFS_MIN_BYTES = "2147483648"
PREPARE_STEP_NAME = "Prepare the private source gate environment"
CLEANUP_STEP_NAME = "Release the private gate tmpfs"
GATE_STEPS = (
    ("build_windows", "Gate 2 - Go tests"),
    ("build_windows", "Gate 3 - Go race detector"),
    ("build_linux", "Run focused Linux release gates"),
)

prepare_steps = {}
for job_name, steps in (("build_windows", windows_steps), ("build_linux", linux_steps)):
    prepare_steps[job_name] = step_named(steps, PREPARE_STEP_NAME)
windows_prepare = prepare_steps["build_windows"]
linux_prepare = prepare_steps["build_linux"]
if serialized(windows_prepare) != serialized(linux_prepare):
    raise SystemExit("both build jobs must prepare the gate environment with one identical step")
prepare_script = windows_prepare["run"]
declared_options = windows_prepare.get("env", {}).get("GATE_TMPFS_OPTIONS", "").split(",")
if not any(option.startswith("size=") and option != "size=" for option in declared_options):
    raise SystemExit(
        "the gate tmpfs must be bounded by an explicit size=, or the scratch can eat the runner's RAM"
    )
for required_option in ("mode=1777", "nosuid", "nodev"):
    if required_option not in declared_options:
        raise SystemExit(f"the gate tmpfs must be mounted {required_option}")
if "noexec" in declared_options:
    raise SystemExit(
        "the gates compile and run helper binaries under their TMPDIR, so the scratch must not be noexec"
    )
if windows_prepare.get("env") != {
    "STRACE_URL": STRACE_URL,
    "STRACE_SHA256": STRACE_SHA256,
    "STRACE_VERSION_LINE": STRACE_VERSION_LINE,
    "GATE_TMPFS": GATE_TMPFS,
    "GATE_TMPFS_OPTIONS": GATE_TMPFS_OPTIONS,
    "GATE_TMPFS_MIN_BYTES": GATE_TMPFS_MIN_BYTES,
    "GATE_FOREIGN_TMPFS": GATE_FOREIGN_TMPFS,
    "GATE_ROOT": GATE_ROOT_EXPRESSION,
    "GATE_TMPDIR": GATE_TMPDIR_EXPRESSION,
}:
    raise SystemExit(
        "the gate preparation step does not pin exactly the audited tarball/version, "
        "the tmpfs with its options, floor and foreign twin, the gate root and the gates' TMPDIR"
    )
if "working-directory" in windows_prepare:
    raise SystemExit("gate preparation must not run inside the private source checkout")

for required in (
    # (a) the official tarball by exact URL, checked strictly against its pin.
    'curl --fail --silent --show-error --location --proto \'=https\' --tlsv1.2 \\',
    '-o "$STRACE_SRC/strace-7.1.tar.xz" "$STRACE_URL"',
    'printf \'%s  %s\\n\' "$STRACE_SHA256" "$STRACE_SRC/strace-7.1.tar.xz" > "$STRACE_SRC/SHA256SUMS"',
    'sha256sum -c --strict "$STRACE_SRC/SHA256SUMS"',
    # (b) the exact recipe the milestone validated on the reference machine.
    './configure --prefix="$STRACE_PREFIX" --enable-mpers=no',
    'make -j"$(nproc)"',
    "make install",
    # (c) the literal tracer identity the pinned syscall table covers.
    'STRACE_PREFIX="$RUNNER_TEMP/strace-7.1"',
    'STRACE_BIN="$STRACE_PREFIX/bin/strace"',
    '"$STRACE_BIN" -V',
    "head -1",
    'if [ "$BUILT_VERSION_LINE" != "$STRACE_VERSION_LINE" ]; then',
    'MACHINE="$(uname -m)"',
    'if [ "$MACHINE" != x86_64 ]; then',
    # (d) neither provisioned path may land in a directory the gates refuse, and
    #     that is settled before anything is elevated or mounted.
    'REAL_HOME="$(getent passwd "$(id -u)" | cut -d: -f6)"',
    'for reserved in "$REAL_HOME" "$RUNNER_TEMP" "${GITHUB_WORKSPACE:-}"; do',
    'for provisioned in "$GATE_ROOT" "$GATE_TMPDIR"; do',
    '"$reserved"/*)',
    # (e) the scratch filesystem is created, not hoped for.
    'sudo mount -t tmpfs -o "$GATE_TMPFS_OPTIONS" tmpfs "$GATE_TMPFS"',
    # (f) and then measured: the type, a device of its own, room, and exec.
    'GATE_FS_TYPE="$(stat -f -c %T "$GATE_TMPFS")"',
    'if [ "$GATE_FS_TYPE" != tmpfs ]; then',
    'GATE_DEVICE="$(stat -c %d "$GATE_TMPFS")"',
    'GATE_FOREIGN_DEVICE="$(stat -c %d "$GATE_FOREIGN_TMPFS")"',
    'if [ "$GATE_DEVICE" = "$GATE_FOREIGN_DEVICE" ]; then',
    'GATE_TMPFS_FREE="$(df --output=avail -B1 "$GATE_TMPFS" | tail -1 | tr -d \' \')"',
    'if [ "$GATE_TMPFS_FREE" -lt "$GATE_TMPFS_MIN_BYTES" ]; then',
    'GATE_EXEC_PROBE="$GATE_TMPDIR/gate-exec-probe"',
    'chmod 700 "$GATE_EXEC_PROBE"',
    'if ! "$GATE_EXEC_PROBE"; then',
    'rm -f "$GATE_EXEC_PROBE"',
    # (g) the required gate root and its task directory. The gates' TMPDIR is the
    #     mount itself, so it is never created, chmodded or removed by hand.
    'rm -rf "$GATE_ROOT"\n',
    'mkdir -m 700 -p "$GATE_ROOT"\n',
    'mkdir -p "$GATE_ROOT/tasks"',
    'chmod 700 "$GATE_ROOT" "$GATE_ROOT/tasks"\n',
    # (h) a real unprivileged user namespace, remediated once and then proven.
    "unshare -U true",
    "sysctl -n kernel.apparmor_restrict_unprivileged_userns",
    "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0",
    # (i) the new tracer reaches the gates through the job PATH only.
    'printf \'%s\\n\' "$STRACE_PREFIX/bin" >> "$GITHUB_PATH"',
):
    if required not in prepare_script:
        raise SystemExit(f"gate preparation is missing {required}")
# The gates' TMPDIR is now the mount point itself. Every form that would have
# treated it as a directory of our own making would operate on /tmp instead.
for destructive in (
    'rm -rf "$GATE_ROOT" "$GATE_TMPDIR"',
    'rm -rf "$GATE_TMPDIR"',
    'mkdir -m 700 -p "$GATE_ROOT" "$GATE_TMPDIR"',
    'chmod 700 "$GATE_ROOT" "$GATE_ROOT/tasks" "$GATE_TMPDIR"',
):
    if destructive in workflow_text:
        raise SystemExit(
            f"the gates' TMPDIR is the mounted tmpfs itself, so {destructive} would operate on {GATE_TMPFS}"
        )
# The strace sources must not be staged on the mount point either: the mount
# would hide them halfway through the step.
if 'STRACE_SRC="$(mktemp -d)"' in prepare_script:
    raise SystemExit(
        "gate preparation must stage the tracer sources under RUNNER_TEMP, not on the scratch it is about to mount over"
    )
if 'STRACE_SRC="$(mktemp -d -p "$RUNNER_TEMP")"' not in prepare_script:
    raise SystemExit("gate preparation must stage the tracer sources under RUNNER_TEMP")
if prepare_script.count(STRACE_VERSION_LINE) != 0:
    raise SystemExit("the tracer version must be compared against the pinned env value, never a literal copy")
if "unshare -U true" in prepare_script and prepare_script.count("unshare -U true") != 2:
    raise SystemExit("gate preparation must prove the user namespace before and after remediation")
if "|| true" in prepare_script or "continue-on-error" in serialized(windows_prepare):
    raise SystemExit("gate preparation must stay fail-closed")
prepare_order = [
    'sha256sum -c --strict "$STRACE_SRC/SHA256SUMS"',
    './configure --prefix="$STRACE_PREFIX" --enable-mpers=no',
    "make install",
    'if [ "$BUILT_VERSION_LINE" != "$STRACE_VERSION_LINE" ]; then',
    'if [ "$MACHINE" != x86_64 ]; then',
    'REAL_HOME="$(getent passwd "$(id -u)" | cut -d: -f6)"',
    'sudo mount -t tmpfs -o "$GATE_TMPFS_OPTIONS" tmpfs "$GATE_TMPFS"',
    'GATE_FS_TYPE="$(stat -f -c %T "$GATE_TMPFS")"',
    'if [ "$GATE_DEVICE" = "$GATE_FOREIGN_DEVICE" ]; then',
    'if [ "$GATE_TMPFS_FREE" -lt "$GATE_TMPFS_MIN_BYTES" ]; then',
    'GATE_EXEC_PROBE="$GATE_TMPDIR/gate-exec-probe"',
    'mkdir -m 700 -p "$GATE_ROOT"\n',
    'mkdir -p "$GATE_ROOT/tasks"',
    "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0",
    'printf \'%s\\n\' "$STRACE_PREFIX/bin" >> "$GITHUB_PATH"',
]
prepare_positions = [prepare_script.index(marker) for marker in prepare_order]
if prepare_positions != sorted(prepare_positions):
    raise SystemExit(
        "gate preparation must verify, build, refuse a reserved target, mount, measure, provision, and only then export"
    )

# The gates' TMPDIR is the mount point itself: that is the whole point of
# mounting over /tmp rather than provisioning a named directory somewhere. Any
# extra path component is charged against the socket budget below.
if GATE_TMPDIR_EXPRESSION != GATE_TMPFS:
    raise SystemExit(
        f"the gates' TMPDIR must be the mounted tmpfs itself ({GATE_TMPFS}), not {GATE_TMPDIR_EXPRESSION}"
    )
if len(GATE_TMPDIR_EXPRESSION) + MEASURED_GATE_SOCKET_SUFFIX >= UNIX_SOCKET_PATH_LIMIT:
    raise SystemExit(
        f"a gate socket under {GATE_TMPDIR_EXPRESSION} reaches "
        f"{len(GATE_TMPDIR_EXPRESSION) + MEASURED_GATE_SOCKET_SUFFIX} bytes, and bind refuses anything "
        f"from {UNIX_SOCKET_PATH_LIMIT} bytes up"
    )
if not GATE_ROOT_EXPRESSION.startswith(GATE_TMPFS + "/") or GATE_ROOT_EXPRESSION.count("/") != GATE_TMPFS.count("/") + 1:
    raise SystemExit(f"the gate root must be a direct child of {GATE_TMPFS}")
for forbidden in (
    "${{ runner.temp }}/jayflow-gate",
    "$RUNNER_TEMP/jayflow-gate",
    "${{ runner.temp }}/jayflow-tmp",
    "$RUNNER_TEMP/jayflow-tmp",
    "${{ github.workspace }}/jayflow-gate",
    # The scratch may not go back to /dev/shm: that prefix is what pushed the
    # gate sockets past the kernel limit, and the broker fixture needs /dev/shm
    # to stay a filesystem the gates are not sitting on.
    GATE_FOREIGN_TMPFS + "/jayflow-gate",
    GATE_FOREIGN_TMPFS + "/jayflow-tmp",
):
    if forbidden in workflow_text:
        raise SystemExit(f"the gate environment must never be provisioned at {forbidden}")

gate_root_steps = []
for job_name, steps in (
    ("build_windows", windows_steps),
    ("build_linux", linux_steps),
    ("accept_linux", accept_steps),
    ("sign_publish", sign_steps),
):
    for step in steps:
        if "JAYFLOW_LOCAL_GATE_ROOT" in serialized(step):
            gate_root_steps.append((job_name, step.get("name")))
if gate_root_steps != list(GATE_STEPS):
    raise SystemExit(
        f"the private gate root is exported to {gate_root_steps}, want exactly {list(GATE_STEPS)}"
    )
for job_name, step_name in GATE_STEPS:
    steps = windows_steps if job_name == "build_windows" else linux_steps
    gate_step = step_named(steps, step_name)
    if gate_step.get("env") != {
        "JAYFLOW_LOCAL_GATE_ROOT": GATE_ROOT_EXPRESSION,
        "TMPDIR": GATE_TMPDIR_EXPRESSION,
    }:
        raise SystemExit(
            f"{job_name}/{step_name} must receive exactly the prepared gate root and the "
            "dedicated tmpfs TMPDIR"
        )

# The dedicated TMPDIR is what moves t.TempDir() off the inode-recycling ext4,
# so it has the same blast radius as the gate root: exactly the three gate
# steps, and nothing else in any job.
tmpdir_steps = []
tmpfs_steps = []
foreign_steps = []
for job_name, steps in (
    ("build_windows", windows_steps),
    ("build_linux", linux_steps),
    ("accept_linux", accept_steps),
    ("sign_publish", sign_steps),
):
    for step in steps:
        if "TMPDIR" in step.get("env", {}):
            tmpdir_steps.append((job_name, step.get("name")))
        # Only the two pinned read-only layout lines of the acceptance
        # diagnostics are exempt, and only inside that one step.
        scan = serialized(step)
        if job_name == "accept_linux" and step.get("name") == ACCEPT_DIAGNOSTICS_STEP_NAME:
            scan = without_diagnostics_layout(scan)
        if names_gate_tmpfs(scan):
            tmpfs_steps.append((job_name, step.get("name")))
        if GATE_FOREIGN_TMPFS in scan:
            foreign_steps.append((job_name, step.get("name")))
if tmpdir_steps != list(GATE_STEPS):
    raise SystemExit(
        f"the gates' TMPDIR is exported to {tmpdir_steps}, want exactly {list(GATE_STEPS)}"
    )
expected_tmpfs_steps = sorted([
    ("build_windows", PREPARE_STEP_NAME),
    ("build_windows", CLEANUP_STEP_NAME),
    ("build_linux", PREPARE_STEP_NAME),
    ("build_linux", CLEANUP_STEP_NAME),
] + list(GATE_STEPS))
if sorted(tmpfs_steps) != expected_tmpfs_steps:
    raise SystemExit(
        f"{GATE_TMPFS} is named by {sorted(tmpfs_steps)}, want exactly {expected_tmpfs_steps}"
    )
# /dev/shm is never scratch here. It is only ever read, by the preparation, as
# the filesystem the scratch must be distinct from.
expected_foreign_steps = sorted([
    ("build_windows", PREPARE_STEP_NAME),
    ("build_linux", PREPARE_STEP_NAME),
])
if sorted(foreign_steps) != expected_foreign_steps:
    raise SystemExit(
        f"{GATE_FOREIGN_TMPFS} is named by {sorted(foreign_steps)}, want exactly {expected_foreign_steps}"
    )

# The preparation mounted a tmpfs over the runner's own /tmp, and everything on
# it is charged against the runner's RAM. Each build job gives the mount back
# unconditionally, including after a failed gate, so the rest of the job and any
# re-run on the same host see the real /tmp again.
cleanups = {}
for job_name, steps in (("build_windows", windows_steps), ("build_linux", linux_steps)):
    cleanup = step_named(steps, CLEANUP_STEP_NAME)
    cleanups[job_name] = cleanup
    if steps[-1] is not cleanup:
        raise SystemExit(f"{job_name} must release the gate tmpfs as its last step")
    if cleanup.get("if") != "always()":
        raise SystemExit(f"{job_name} tmpfs cleanup must run with if: always()")
    if cleanup.get("env") != {"GATE_TMPFS": GATE_TMPFS}:
        raise SystemExit(f"{job_name} tmpfs cleanup must name exactly the mounted scratch")
    if "working-directory" in cleanup:
        raise SystemExit(f"{job_name} tmpfs cleanup must not run inside the private source checkout")
    for required in (
        "set -euo pipefail",
        'if mountpoint -q "$GATE_TMPFS"; then',
        # Lazy, because a gate that died may still be holding descriptors on the
        # scratch and a plain umount would fail the always() step.
        'sudo umount -l "$GATE_TMPFS"',
    ):
        if required not in cleanup["run"]:
            raise SystemExit(f"{job_name} tmpfs cleanup is missing {required}")
    if "rm -rf" in cleanup["run"]:
        raise SystemExit(
            f"{job_name} tmpfs cleanup must release the mount, never delete paths on the runner's /tmp"
        )
if serialized(cleanups["build_windows"]) != serialized(cleanups["build_linux"]):
    raise SystemExit("both build jobs must release the gate tmpfs with one identical step")
cleanup_script = cleanups["build_windows"]["run"]

# The gate environment is allowed exactly three elevations, each pinned by name
# and by target: the userns sysctl, and the mount and unmount of the scratch.
# Nothing else in either script may reach for root.
GATE_ELEVATIONS = (
    'sudo mount -t tmpfs -o "$GATE_TMPFS_OPTIONS" tmpfs "$GATE_TMPFS"',
    "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0",
    'sudo umount -l "$GATE_TMPFS"',
)
for label, script, expected in (
    ("preparation", prepare_script, {GATE_ELEVATIONS[0]: 1, GATE_ELEVATIONS[1]: 1}),
    ("cleanup", cleanup_script, {GATE_ELEVATIONS[2]: 1}),
):
    found = {}
    for match in re.finditer(r"sudo\b[^\n]*", script):
        elevation = match.group(0).strip()
        if elevation not in GATE_ELEVATIONS:
            raise SystemExit(
                f"gate {label} may only elevate for {list(GATE_ELEVATIONS)}, found {elevation!r}"
            )
        found[elevation] = found.get(elevation, 0) + 1
    if found != expected:
        raise SystemExit(f"gate {label} elevations are {found}, want {expected}")

# Each pinned layout line may appear exactly once in the whole job, and only
# inside the diagnostics step: anywhere else, or twice, and the exemption below
# would be laundering a second use of the gate scratch.
accept_diagnostics_steps = [
    step for step in accept_steps if step.get("name") == ACCEPT_DIAGNOSTICS_STEP_NAME
]
for line in ACCEPT_DIAGNOSTICS_LAYOUT_LINES:
    if accept_text.count(line) != 1:
        raise SystemExit(
            f"the acceptance layout probe {line!r} must appear exactly once in accept_linux"
        )
    if len(accept_diagnostics_steps) != 1 or line not in serialized(accept_diagnostics_steps[0]):
        raise SystemExit(
            f"only {ACCEPT_DIAGNOSTICS_STEP_NAME!r} may name the runner layout: {line!r}"
        )
accept_scan_text = without_diagnostics_layout(accept_text)

for forbidden in (
    "JAYFLOW_LOCAL_GATE_ROOT",
    "jayflow-gate",
    "jayflow-tmp",
    "strace",
    "TMPDIR",
    "GATE_TMPFS",
    GATE_FOREIGN_TMPFS,
):
    if forbidden in sign_text:
        raise SystemExit(f"the signing job must never receive the private gate environment: {forbidden}")
    if forbidden in accept_scan_text:
        raise SystemExit(f"the transported-byte acceptance job must not carry the gate environment: {forbidden}")
for label, text in (("signing job", sign_text), ("transported-byte acceptance job", accept_scan_text)):
    if names_gate_tmpfs(text):
        raise SystemExit(f"the {label} must never name the gate scratch {GATE_TMPFS}")
for job_name, steps in (("build_windows", windows_steps), ("build_linux", linux_steps)):
    exporters = [
        step.get("name") for step in steps
        if "$GITHUB_PATH" in str(step.get("run", "")) and "strace" in str(step.get("run", ""))
    ]
    if exporters != [PREPARE_STEP_NAME]:
        raise SystemExit(f"{job_name} may only put the pinned tracer on PATH from the preparation step")

with tempfile.TemporaryDirectory() as prepare_temp_text:
    prepare_temp = pathlib.Path(prepare_temp_text)
    fake_bin = prepare_temp / "fake-bin"
    fake_bin.mkdir()
    tarball_payload = b"fixture strace-7.1 tarball bytes\n"
    tarball_digest = hashlib.sha256(tarball_payload).hexdigest()
    (prepare_temp / "payload").write_bytes(tarball_payload)

    (fake_bin / "curl").write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with pathlib.Path(os.environ["FAKE_PREPARE_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"tool": "curl", "args": args}) + "\n")
if os.environ.get("FAKE_PREPARE_FAILURE") == "download":
    raise SystemExit(22)
destination = pathlib.Path(args[args.index("-o") + 1])
destination.write_bytes(pathlib.Path(os.environ["FAKE_PREPARE_PAYLOAD"]).read_bytes())
''', encoding="utf-8")

    (fake_bin / "tar").write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with pathlib.Path(os.environ["FAKE_PREPARE_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"tool": "tar", "args": args}) + "\n")
destination = pathlib.Path(args[args.index("-C") + 1]) / "strace-7.1"
destination.mkdir(parents=True, exist_ok=True)
configure = destination / "configure"
configure.write_text(
    "#!/usr/bin/env python3\n"
    "import json, os, pathlib, sys\n"
    "args = sys.argv[1:]\n"
    "handle = pathlib.Path(os.environ['FAKE_PREPARE_LOG']).open('a', encoding='utf-8')\n"
    "handle.write(json.dumps({'tool': 'configure', 'args': args}) + '\\n')\n"
    "handle.close()\n"
    "if os.environ.get('FAKE_PREPARE_FAILURE') == 'configure':\n"
    "    raise SystemExit(1)\n"
    "prefix = [a.split('=', 1)[1] for a in args if a.startswith('--prefix=')][0]\n"
    "pathlib.Path(os.environ['FAKE_PREPARE_PREFIX']).write_text(prefix, encoding='utf-8')\n",
    encoding="utf-8",
)
configure.chmod(0o755)
''', encoding="utf-8")

    (fake_bin / "make").write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with pathlib.Path(os.environ["FAKE_PREPARE_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"tool": "make", "args": args}) + "\n")
if os.environ.get("FAKE_PREPARE_FAILURE") == "make":
    raise SystemExit(2)
if args != ["install"]:
    raise SystemExit(0)
prefix = pathlib.Path(pathlib.Path(os.environ["FAKE_PREPARE_PREFIX"]).read_text(encoding="utf-8"))
(prefix / "bin").mkdir(parents=True, exist_ok=True)
tracer = prefix / "bin" / "strace"
tracer.write_text(
    "#!/usr/bin/env bash\n"
    "printf '%s\\n' \"$FAKE_PREPARE_STRACE_VERSION\"\n"
    "printf 'Copyright fixture\\nlicense fixture\\nthere is NO warranty\\n'\n",
    encoding="utf-8",
)
tracer.chmod(0o755)
''', encoding="utf-8")

    (fake_bin / "unshare").write_text(r'''#!/usr/bin/env bash
printf 'unshare %s\n' "$*" >> "$FAKE_PREPARE_TOOLS"
[ "$(cat "$FAKE_PREPARE_USERNS")" = ok ] || exit 1
exit 0
''', encoding="utf-8")

    (fake_bin / "sysctl").write_text(r'''#!/usr/bin/env bash
printf 'sysctl %s\n' "$*" >> "$FAKE_PREPARE_TOOLS"
case "${1:-}" in
  -n) printf '%s\n' "$FAKE_PREPARE_APPARMOR" ;;
  -w) [ "${FAKE_PREPARE_USERNS_FIXABLE:-1}" != 1 ] || printf 'ok' > "$FAKE_PREPARE_USERNS" ;;
  *) exit 64 ;;
esac
exit 0
''', encoding="utf-8")

    (fake_bin / "sudo").write_text(r'''#!/usr/bin/env bash
printf 'sudo %s\n' "$*" >> "$FAKE_PREPARE_TOOLS"
exec "$@"
''', encoding="utf-8")

    (fake_bin / "mount").write_text(r'''#!/usr/bin/env bash
printf 'mount %s\n' "$*" >> "$FAKE_PREPARE_TOOLS"
exit "${FAKE_PREPARE_MOUNT_RC:-0}"
''', encoding="utf-8")

    (fake_bin / "umount").write_text(r'''#!/usr/bin/env bash
printf 'umount %s\n' "$*" >> "$FAKE_PREPARE_TOOLS"
exit 0
''', encoding="utf-8")

    (fake_bin / "mountpoint").write_text(r'''#!/usr/bin/env bash
printf 'mountpoint %s\n' "$*" >> "$FAKE_PREPARE_TOOLS"
exit "${FAKE_PREPARE_MOUNTED:-0}"
''', encoding="utf-8")

    (fake_bin / "uname").write_text(r'''#!/usr/bin/env bash
printf '%s\n' "$FAKE_PREPARE_MACHINE"
''', encoding="utf-8")

    (fake_bin / "nproc").write_text("#!/usr/bin/env bash\nprintf '2\\n'\n", encoding="utf-8")

    # stat -f, stat -c %d and df answer for the fixture tmpfs, because the
    # fixture is never really mounted; every other stat call is the real one, so
    # the mode and ownership assertions stay honest.
    (fake_bin / "stat").write_text(r'''#!/usr/bin/env bash
if [ "${1:-}" = -f ]; then
  printf '%s\n' "$FAKE_PREPARE_FSTYPE"
  exit 0
fi
if [ "${1:-}" = -c ] && [ "${2:-}" = %d ]; then
  case "${3:-}" in
    /dev/shm) printf '%s\n' "$FAKE_PREPARE_FOREIGN_DEVICE" ;;
    *) printf '%s\n' "$FAKE_PREPARE_DEVICE" ;;
  esac
  exit 0
fi
exec /usr/bin/stat "$@"
''', encoding="utf-8")

    (fake_bin / "df").write_text(r'''#!/usr/bin/env bash
printf 'Avail\n%s\n' "$FAKE_PREPARE_FREE"
''', encoding="utf-8")

    for stub in fake_bin.iterdir():
        stub.chmod(0o755)

    real_home = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir)

    def run_prepare(scenario, *, failure="", userns="ok", apparmor="0", fixable="1",
                    machine="x86_64", version=STRACE_VERSION_LINE, sha=None,
                    fstype="tmpfs", free="8589934592", device="45", foreign_device="26",
                    mount_rc="0", scratch_mode=None, gate_root=None, gate_tmpdir=None):
        scenario_root = prepare_temp / scenario
        scenario_root.mkdir()
        runner_temp = scenario_root / "runner-temp"
        runner_temp.mkdir()
        scratch = scenario_root / "gate-tmpfs"
        scratch.mkdir()
        workspace = scenario_root / "workspace"

        def resolved(candidate, default):
            if candidate is None:
                return str(default)
            return candidate.replace("@RUNNER_TEMP@", str(runner_temp)).replace(
                "@WORKSPACE@", str(workspace)
            )
        github_path = scenario_root / "github-path"
        state = scenario_root / "userns"
        state.write_text(userns, encoding="utf-8")
        log = scenario_root / "calls.jsonl"
        log.touch()
        tools = scenario_root / "tools.log"
        tools.touch()
        env = safe_env.copy()
        env.update({
            "PATH": str(fake_bin) + os.pathsep + safe_env["PATH"],
            "RUNNER_TEMP": str(runner_temp),
            "GITHUB_PATH": str(github_path),
            "STRACE_URL": STRACE_URL,
            "STRACE_SHA256": tarball_digest if sha is None else sha,
            "STRACE_VERSION_LINE": STRACE_VERSION_LINE,
            "GATE_TMPFS": str(scratch),
            "GATE_TMPFS_OPTIONS": GATE_TMPFS_OPTIONS,
            "GATE_TMPFS_MIN_BYTES": GATE_TMPFS_MIN_BYTES,
            "GATE_FOREIGN_TMPFS": GATE_FOREIGN_TMPFS,
            "GATE_ROOT": resolved(gate_root, scratch / "jayflow-gate"),
            "GATE_TMPDIR": resolved(gate_tmpdir, scratch),
            "GITHUB_WORKSPACE": str(workspace),
            "FAKE_PREPARE_FSTYPE": fstype,
            "FAKE_PREPARE_FREE": free,
            "FAKE_PREPARE_DEVICE": device,
            "FAKE_PREPARE_FOREIGN_DEVICE": foreign_device,
            "FAKE_PREPARE_MOUNT_RC": mount_rc,
            "FAKE_PREPARE_LOG": str(log),
            "FAKE_PREPARE_TOOLS": str(tools),
            "FAKE_PREPARE_PAYLOAD": str(prepare_temp / "payload"),
            "FAKE_PREPARE_PREFIX": str(scenario_root / "prefix"),
            "FAKE_PREPARE_USERNS": str(state),
            "FAKE_PREPARE_USERNS_FIXABLE": fixable,
            "FAKE_PREPARE_APPARMOR": apparmor,
            "FAKE_PREPARE_MACHINE": machine,
            "FAKE_PREPARE_STRACE_VERSION": version,
            "FAKE_PREPARE_FAILURE": failure,
        })
        if scratch_mode is not None:
            scratch.chmod(scratch_mode)
        try:
            result = checked(["bash", "-c", prepare_script], cwd=scenario_root, env=env)
        finally:
            if scratch_mode is not None:
                scratch.chmod(0o755)
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
        return result, calls, tools.read_text(encoding="utf-8"), github_path, runner_temp, scratch

    result, calls, tools_log, github_path, runner_temp, scratch = run_prepare("clean")
    require_success(result, "behavioral gate environment preparation")
    curl_calls = [call for call in calls if call["tool"] == "curl"]
    if len(curl_calls) != 1 or STRACE_URL not in curl_calls[0]["args"]:
        raise SystemExit(f"gate preparation must fetch exactly the pinned tarball URL once: {curl_calls}")
    configure_calls = [call for call in calls if call["tool"] == "configure"]
    if len(configure_calls) != 1 or configure_calls[0]["args"] != [
        f"--prefix={runner_temp}/strace-7.1", "--enable-mpers=no"
    ]:
        raise SystemExit(f"gate preparation configure arguments are not the audited recipe: {configure_calls}")
    make_calls = [call["args"] for call in calls if call["tool"] == "make"]
    if make_calls != [["-j2"], ["install"]]:
        raise SystemExit(f"gate preparation must build then install the pinned tracer: {make_calls}")
    gate_root = scratch / "jayflow-gate"
    if not (gate_root / "tasks").is_dir():
        raise SystemExit("gate preparation did not create the required tasks directory under the gate root")
    for directory in (gate_root, gate_root / "tasks"):
        if oct(directory.stat().st_mode & 0o777) != "0o700":
            raise SystemExit(f"{directory} must be exactly mode 0700")
    if (runner_temp / "jayflow-gate").exists() or (runner_temp / "jayflow-tmp").exists():
        raise SystemExit("gate preparation provisioned the gates inside the runner temp")
    if github_path.read_text(encoding="utf-8") != f"{runner_temp}/strace-7.1/bin\n":
        raise SystemExit("gate preparation must prepend exactly the built tracer directory to PATH")
    if "sysctl -w" in tools_log:
        raise SystemExit("gate preparation relaxed the kernel although the namespace already worked")
    # The scratch is mounted, once, with exactly the audited options, and the
    # preparation never unmounts anything.
    mounted = f"sudo mount -t tmpfs -o {GATE_TMPFS_OPTIONS} tmpfs {scratch}"
    if tools_log.count(mounted) != 1:
        raise SystemExit(f"gate preparation must mount the scratch exactly once as {mounted!r}: {tools_log!r}")
    if "umount" in tools_log:
        raise SystemExit("gate preparation must not unmount anything; that is the cleanup step's job")
    # Every elevation the preparation actually performed is on the pinned list.
    performed_elevations = {mounted, "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"}
    for line in tools_log.splitlines():
        if line.startswith("sudo ") and line not in performed_elevations:
            raise SystemExit(f"gate preparation elevated for something unpinned: {line!r}")
    # The exec probe proves the mount, then leaves nothing behind.
    if (scratch / "gate-exec-probe").exists():
        raise SystemExit("gate preparation left its exec probe on the scratch")

    result, calls, tools_log, github_path, runner_temp, scratch = run_prepare(
        "restricted", userns="blocked", apparmor="1"
    )
    require_success(result, "behavioral gate preparation under AppArmor userns restriction")
    if "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0" not in tools_log:
        raise SystemExit("a restricted runner must be remediated with the exact sysctl write")
    if tools_log.count("unshare -U true") != 2:
        raise SystemExit("remediation must be re-proven with a second real unshare")
    if not github_path.exists():
        raise SystemExit("a remediated runner must still export the prepared environment")

    for scenario, options in (
        ("sha-mismatch", {"sha": "0" * 64}),
        ("download-failure", {"failure": "download"}),
        ("configure-failure", {"failure": "configure"}),
        ("make-failure", {"failure": "make"}),
        ("wrong-tracer-version", {"version": "strace -- version 6.8"}),
        ("wrong-tracer-patch", {"version": "strace -- version 7.1.1"}),
        ("wrong-machine", {"machine": "aarch64"}),
        ("userns-unavailable", {"userns": "blocked", "apparmor": "0"}),
        ("userns-unfixable", {"userns": "blocked", "apparmor": "1", "fixable": "0"}),
        # The scratch is measured after it is mounted: an ext4 gate root
        # reinstates the immediate inode recycling the identity races fail on,
        # and a mount that did not take is not silently used.
        ("scratch-not-tmpfs", {"fstype": "ext2/ext3"}),
        ("scratch-tmpfs-too-small", {"free": "2147483647"}),
        ("scratch-mount-refused", {"mount_rc": "32"}),
        # cmd/jayflowd/fsbroker_linux_test.go opens one fixture on the gates'
        # TMPDIR and one on /dev/shm and requires two distinct devices.
        ("scratch-shares-device-with-shm", {"device": "26", "foreign_device": "26"}),
        # A scratch the gates cannot write or execute out of fails them for a
        # reason that would read as a product defect.
        ("scratch-refuses-the-exec-probe", {"scratch_mode": 0o500}),
        # Neither provisioned path may land where the gates refuse to work.
        ("gate-root-inside-home", {"gate_root": str(real_home / "jayflow-gate")}),
        ("gate-tmpdir-inside-home", {"gate_tmpdir": str(real_home / "jayflow-tmp")}),
        ("gate-root-inside-runner-temp", {"gate_root": "@RUNNER_TEMP@/jayflow-gate"}),
        ("gate-tmpdir-inside-runner-temp", {"gate_tmpdir": "@RUNNER_TEMP@/jayflow-tmp"}),
        ("gate-root-inside-workspace", {"gate_root": "@WORKSPACE@/jayflow-gate"}),
    ):
        result, calls, tools_log, github_path, runner_temp, scratch = run_prepare(scenario, **options)
        if result.returncode == 0:
            raise SystemExit(f"gate preparation accepted injected failure {scenario}")
        if github_path.exists():
            raise SystemExit(f"gate preparation exported the environment despite failure {scenario}")
        if scenario == "sha-mismatch" and any(call["tool"] in {"configure", "make"} for call in calls):
            raise SystemExit("an unverified tarball must never be configured or built")
        if scenario.startswith("gate-") and "mount" in tools_log:
            raise SystemExit(f"{scenario} mounted the scratch before refusing a target the gates reject")
        for refused in (real_home / "jayflow-gate", real_home / "jayflow-tmp"):
            if refused.exists():
                raise SystemExit(f"{scenario} created {refused} inside the real home before refusing")

    # The cleanup step must give the mount back lazily when the preparation took
    # it, must stay quiet when it did not, and must never delete anything: on a
    # runner where the mount is missing, the paths it would delete are the
    # runner's own /tmp.
    cleanup_root = prepare_temp / "cleanup"
    cleanup_root.mkdir()
    for scenario, mountpoint_rc, want_release in (
        ("mounted", "0", True),
        ("never-mounted", "1", False),
    ):
        scenario_root = cleanup_root / scenario
        scenario_root.mkdir()
        scratch = scenario_root / "gate-tmpfs"
        scratch.mkdir()
        survivor = scratch / "runner-owned-file"
        survivor.write_bytes(b"the runner's own /tmp")
        tools = scenario_root / "tools.log"
        tools.touch()
        cleanup_env = safe_env.copy()
        cleanup_env.update({
            "PATH": str(fake_bin) + os.pathsep + safe_env["PATH"],
            "GATE_TMPFS": str(scratch),
            "FAKE_PREPARE_TOOLS": str(tools),
            "FAKE_PREPARE_MOUNTED": mountpoint_rc,
        })
        cleanup_result = checked(["bash", "-c", cleanup_script], cwd=scenario_root, env=cleanup_env)
        require_success(cleanup_result, f"behavioral gate tmpfs cleanup ({scenario})")
        tools_log = tools.read_text(encoding="utf-8")
        released = f"sudo umount -l {scratch}" in tools_log
        if released != want_release:
            raise SystemExit(
                f"gate cleanup ({scenario}) {'did not release' if want_release else 'released'} "
                f"the scratch: {tools_log!r}"
            )
        if not survivor.exists():
            raise SystemExit(f"gate cleanup ({scenario}) deleted content instead of releasing the mount")
        for line in tools_log.splitlines():
            if line.startswith("sudo ") and line != f"sudo umount -l {scratch}":
                raise SystemExit(f"gate cleanup elevated for something unpinned: {line!r}")


linux_build_step = step_named(linux_steps, "Build and audit reproducible Linux gateway")
if linux_build_step.get("working-directory") != "source" or linux_build_step.get("env") != {
    "VERSION": "${{ steps.inputs.outputs.version }}",
    "SOURCE_SHA": "${{ steps.source.outputs.sha }}",
    "PUBLIC_KEY": "${{ vars.JAYFLOW_RELEASE_PUBLIC_KEY }}",
}:
    raise SystemExit("Linux build identity is not bound to resolved source/public key")
linux_build_script = linux_build_step["run"]
for required in (
    "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=true",
    '-ldflags "-s -w -X main.Version=${VERSION} -X main.SourceSHA=${SOURCE_SHA} -X github.com/julubileu/jayflow-v2/internal/updater.PublicKeyBase64=${PUBLIC_KEY}"',
    './cmd/jayflow-web',
    'build_gateway "$RUNNER_TEMP/linux-first/jayflow-web-${VERSION}-linux-amd64"',
    'build_gateway "dist-linux/jayflow-web-${VERSION}-linux-amd64"',
    'cmp -s "$RUNNER_TEMP/linux-first/jayflow-web-${VERSION}-linux-amd64" "dist-linux/jayflow-web-${VERSION}-linux-amd64"',
    "ACTUAL_ASSETS",
    'stat -c \'%a\' "$GATEWAY"',
    'audit-linux',
    'IDENTITY="$(dist-linux/jayflow-web-${VERSION}-linux-amd64 version --json)"',
    'want = {"version": sys.argv[2], "goos": "linux", "goarch": "amd64", "source_sha": sys.argv[3]}',
):
    if required not in linux_build_script:
        raise SystemExit(f"Linux reproducible build is missing {required}")
if "git diff --exit-code" not in linux_build_script or "git ls-files --others --exclude-standard" not in linux_build_script:
    raise SystemExit("Linux build must recheck a clean source tree immediately around the build")

with tempfile.TemporaryDirectory() as linux_temp_text:
    linux_temp = pathlib.Path(linux_temp_text)
    project = linux_temp / "source"
    project.mkdir()
    fake_bin = linux_temp / "fake-bin"
    fake_bin.mkdir()
    go_log = linux_temp / "go.jsonl"
    fake_go = fake_bin / "go"
    fake_go.write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
with pathlib.Path(os.environ["FAKE_GO_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"args": args, "cgo": os.environ.get("CGO_ENABLED"), "goos": os.environ.get("GOOS"), "goarch": os.environ.get("GOARCH")}) + "\n")
if not args or args[0] != "build":
    raise SystemExit("unexpected fake go invocation")
output = pathlib.Path(args[args.index("-o") + 1])
counter = pathlib.Path(os.environ["FAKE_GO_COUNT"])
count = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(count))
failure = os.environ.get("FAKE_LINUX_FAILURE", "")
if failure == "missing-elf" and count == 2:
    raise SystemExit(0)
output.parent.mkdir(parents=True, exist_ok=True)
version = os.environ["VERSION"]
sha = os.environ["SOURCE_SHA"]
identity = {"version": version, "goos": "linux", "goarch": "amd64", "source_sha": sha}
if failure == "wrong-json-identity": identity["goarch"] = "arm64"
if failure == "wrong-source-sha": identity["source_sha"] = "f" * 40
body = "#!/usr/bin/env python3\nimport json\nprint(json.dumps(" + repr(identity) + ", separators=(',', ':')))\n"
if failure == "build-mismatch" and count == 2: body += "# mismatch\n"
output.write_text(body, encoding="utf-8")
output.chmod(0o644 if failure == "non-executable" else 0o755)
if failure == "multiple-linux-files" and count == 2:
    (output.parent / "extra-linux-file").write_text("extra", encoding="utf-8")
''', encoding="utf-8")
    fake_go.chmod(0o755)
    fake_git = fake_bin / "git"
    fake_git.write_text(r'''#!/usr/bin/env bash
if [ "${FAKE_LINUX_FAILURE:-}" = dirty-source ] && [ "${1:-}" = diff ]; then exit 1; fi
if [ "${1:-}" = ls-files ]; then exit 0; fi
exit 0
''', encoding="utf-8")
    fake_git.chmod(0o755)
    runner_temp = linux_temp / "runner"
    runner_temp.mkdir()
    fake_auditor = runner_temp / "jayflow-release-tool"
    fake_auditor.write_text(r'''#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_AUDIT_LOG"
case "${FAKE_LINUX_FAILURE:-}" in wrong-public-key-marker|audit-linux) exit 42;; esac
exit 0
''', encoding="utf-8")
    fake_auditor.chmod(0o755)
    linux_env = safe_env.copy()
    linux_env.update({
        "PATH": str(fake_bin) + os.pathsep + safe_env["PATH"],
        "VERSION": "2.0.33-dev",
        "SOURCE_SHA": "0123456789abcdef0123456789abcdef01234567",
        "PUBLIC_KEY": "dGVzdC1wdWJsaWMta2V5",
        "RUNNER_TEMP": str(runner_temp),
        "FAKE_GO_LOG": str(go_log),
        "FAKE_GO_COUNT": str(linux_temp / "go-count"),
        "FAKE_AUDIT_LOG": str(linux_temp / "audit.log"),
    })

    result = checked(["bash", "-c", linux_build_script], cwd=project, env=linux_env)
    require_success(result, "behavioral reproducible Linux build")
    go_calls = [json.loads(line) for line in go_log.read_text(encoding="utf-8").splitlines()]
    if len(go_calls) != 2:
        raise SystemExit("Linux workflow must invoke go build exactly twice")
    for call in go_calls:
        if (call["cgo"], call["goos"], call["goarch"]) != ("0", "linux", "amd64"):
            raise SystemExit(f"Linux build environment is not exact: {call}")
        args = call["args"]
        for required in ("build", "-trimpath", "-buildvcs=true", "-ldflags", "./cmd/jayflow-web"):
            if required not in args:
                raise SystemExit(f"Linux go invocation is missing {required}: {args}")
        ldflags = args[args.index("-ldflags") + 1]
        want_ldflags = "-s -w -X main.Version=2.0.33-dev -X main.SourceSHA=0123456789abcdef0123456789abcdef01234567 -X github.com/julubileu/jayflow-v2/internal/updater.PublicKeyBase64=dGVzdC1wdWJsaWMta2V5"
        if ldflags != want_ldflags:
            raise SystemExit(f"Linux ldflags are {ldflags!r}, want {want_ldflags!r}")

    def build_command_without_output(args):
        index = args.index("-o")
        return args[:index] + args[index + 2:]

    if build_command_without_output(go_calls[0]["args"]) != build_command_without_output(go_calls[1]["args"]):
        raise SystemExit(
            "both Linux builds must issue one byte-identical command except -o: "
            f"{go_calls[0]['args']!r} vs {go_calls[1]['args']!r}"
        )
    build_outputs = [call["args"][call["args"].index("-o") + 1] for call in go_calls]
    if len(set(build_outputs)) != 2:
        raise SystemExit("the two Linux builds must use two distinct clean output directories")
    if [pathlib.PurePosixPath(output).name for output in build_outputs] != [
        "jayflow-web-2.0.33-dev-linux-amd64"
    ] * 2:
        raise SystemExit(f"Linux build outputs are not the exact artifact name: {build_outputs!r}")
    if not build_outputs[0].startswith(str(runner_temp) + os.sep):
        raise SystemExit("the first Linux build must land in a clean runner-temporary directory")
    if build_outputs[1] != "dist-linux/jayflow-web-2.0.33-dev-linux-amd64":
        raise SystemExit("the published Linux build must land in the isolated dist-linux directory")

    for failure in (
        "build-mismatch", "missing-elf", "multiple-linux-files", "non-executable",
        "dirty-source", "wrong-json-identity", "wrong-source-sha",
        "wrong-public-key-marker", "audit-linux",
    ):
        shutil.rmtree(project / "dist-linux", ignore_errors=True)
        shutil.rmtree(runner_temp / "linux-first", ignore_errors=True)
        for path in (linux_temp / "go-count", go_log, linux_temp / "audit.log"):
            path.unlink(missing_ok=True)
        failing_env = linux_env.copy()
        failing_env["FAKE_LINUX_FAILURE"] = failure
        result = checked(["bash", "-c", linux_build_script], cwd=project, env=failing_env)
        if result.returncode == 0:
            raise SystemExit(f"behavioral Linux build accepted injected failure {failure}")

accept_audit = step_named(accept_steps, "Audit transported Linux bytes")
if accept_audit.get("env") != {
    "VERSION": "${{ needs.build_linux.outputs.version }}",
    "SOURCE_SHA": "${{ needs.build_linux.outputs.source_sha }}",
    "PUBLIC_KEY": "${{ vars.JAYFLOW_RELEASE_PUBLIC_KEY }}",
}:
    raise SystemExit("accept_linux audit is not bound to transported build identity")
for required in ("audit-linux", 'candidate/jayflow-web-${VERSION}-linux-amd64'):
    if required not in accept_audit["run"]:
        raise SystemExit(f"accept_linux static audit is missing {required}")

browser_script = scripts["Expose the runner browser as Chromium"]
for candidate in ("/usr/bin/google-chrome-stable", "/usr/bin/google-chrome", "/usr/bin/chromium"):
    if candidate not in browser_script:
        raise SystemExit(f"accept_linux browser discovery is missing {candidate}")
install_accept = scripts["Install acceptance frontend dependencies"]
if "npm ci --prefix cmd/jayflow/frontend --ignore-scripts --no-audit --no-fund" not in install_accept:
    raise SystemExit("accept_linux must use npm ci --ignore-scripts without lifecycle/network extras")
for forbidden in ("playwright install", "npx playwright", "npm install"):
    if forbidden in accept_text:
        raise SystemExit(f"accept_linux must not download a browser or use unpinned install: {forbidden}")

# ---- the acceptance inputs are staged outside the runner home --------------
# Everything the disposable user has to read is copied to ACCEPTANCE_ROOT and
# made a+rX there. The copies are `install`/`cp -RL`, never links: a symlink
# under /opt still resolves back into /home/runner, and the harness itself
# refuses a symlinked input outright.
stage_step = step_named(accept_steps, ACCEPT_STAGE_STEP_NAME)
if accept_steps.index(stage_step) != accept_steps.index(
    step_named(accept_steps, "Run real-systemd and Playwright acceptance")
) - 1:
    raise SystemExit(
        "the acceptance inputs must be staged in the step immediately before the acceptance"
    )
if stage_step.get("env") != {"VERSION": "${{ needs.build_linux.outputs.version }}"}:
    raise SystemExit("the staging step must be bound to exactly the build_linux version")
if "working-directory" in stage_step:
    raise SystemExit("the staging step must run from the workspace root, not inside a checkout")
stage_script = stage_step["run"]
STAGE_REQUIRED = (
    "set -euo pipefail",
    f'ACCEPTANCE_ROOT={ACCEPTANCE_ROOT}',
    # Fail closed rather than copy into whatever a previous run left behind.
    'if [ -e "$ACCEPTANCE_ROOT" ]; then',
    # root-owned tree, world-traversable, on a filesystem the runner home does
    # not gate.
    "sudo install -d -m 0755 -o root -g root",
    '"$ACCEPTANCE_ROOT" "$ACCEPTANCE_ROOT/tests" "$ACCEPTANCE_ROOT/scripts" "$ACCEPTANCE_ROOT/node_modules"',
    # The two executables, under the names the harness demands: the gateway
    # carries the release version, the daemon is plain jayflowd.
    "sudo install -m 0755 -o root -g root",
    '-- "$GATEWAY_SOURCE" "$ACCEPTANCE_ROOT/jayflow-web-${VERSION}-linux-amd64"',
    '-- "$DAEMON_SOURCE" "$ACCEPTANCE_ROOT/jayflowd"',
    # The harness and the Playwright script are data, staged 0644.
    "sudo install -m 0644 -o root -g root",
    '-- source/tests/mobile-release-systemd.sh "$ACCEPTANCE_ROOT/tests/mobile-release-systemd.sh"',
    "-- source/cmd/jayflow/frontend/scripts/mobile-release.playwright.mjs",
    '"$ACCEPTANCE_ROOT/scripts/mobile-release.playwright.mjs"',
    # node resolves playwright-core by walking up from the script, so the
    # package has to be a real directory beside scripts/. -L, never a link.
    "sudo cp -RL",
    "-- source/cmd/jayflow/frontend/node_modules/playwright-core",
    '"$ACCEPTANCE_ROOT/node_modules/playwright-core"',
    'sudo chmod -R a+rX "$ACCEPTANCE_ROOT"',
)
for required in STAGE_REQUIRED:
    if required not in stage_script:
        raise SystemExit(f"the acceptance staging step is missing: {required}")
# The traversable bit is the whole point of the step: without it root's 0755
# directories still hide 0700 subtrees copied out of the npm cache.
if 'sudo chmod -R a+rX "$ACCEPTANCE_ROOT"' not in stage_script:
    raise SystemExit("the staged tree must end up readable and traversable by the disposable user")
stage_writes = [
    line.strip().rstrip("\\").strip()
    for line in stage_script.splitlines()
    if not line.strip().startswith("#") and line.strip().startswith("sudo ")
]
if stage_writes[-1] != 'sudo chmod -R a+rX "$ACCEPTANCE_ROOT"':
    raise SystemExit(
        f"the staging step must finish by opening the tree, last elevation is {stage_writes[-1]!r}"
    )
for forbidden in ("ln -s", "ln -sfn", "cp -a", "cp -r ", "cp -R ", "mv "):
    if forbidden in stage_script:
        raise SystemExit(f"the staged tree must be a dereferenced copy, found: {forbidden}")
# The staged bytes have to be the SAME bytes the auditors accepted: a copy that
# silently truncated would still start, and the acceptance would then be proving
# a byte no release ever ships.
for required in (
    'GATEWAY_SHA256="$(sha256sum -- "$GATEWAY_SOURCE" | cut -d\' \' -f1)"',
    'DAEMON_SHA256="$(sha256sum -- "$DAEMON_SOURCE" | cut -d\' \' -f1)"',
    'STAGED_GATEWAY_SHA256="$(sha256sum -- "$ACCEPTANCE_ROOT/jayflow-web-${VERSION}-linux-amd64" | cut -d\' \' -f1)"',
    'STAGED_DAEMON_SHA256="$(sha256sum -- "$ACCEPTANCE_ROOT/jayflowd" | cut -d\' \' -f1)"',
    'if [ "$GATEWAY_SHA256" != "$STAGED_GATEWAY_SHA256" ]; then',
    'if [ "$DAEMON_SHA256" != "$STAGED_DAEMON_SHA256" ]; then',
    # Both digests land in the job log, so a later run can be compared against
    # what build_linux and the acceptance auditor recorded.
    "printf 'staged gateway sha256: %s\\n' \"$STAGED_GATEWAY_SHA256\"",
    "printf 'staged daemon sha256: %s\\n' \"$STAGED_DAEMON_SHA256\"",
):
    if required not in stage_script:
        raise SystemExit(f"the staging step does not verify the transported bytes: {required}")
# A symlink anywhere in the staged tree is a path back under the runner home,
# and the harness refuses a symlinked input anyway.
if 'find "$ACCEPTANCE_ROOT" -type l' not in stage_script:
    raise SystemExit("the staging step must prove the staged tree holds no symlink")

# Behavioural: the staging step really has to produce a tree the disposable user
# could traverse, out of the same bytes the auditors accepted. The absolute
# staged root cannot exist inside a sandbox, so the simulation relocates exactly
# that prefix - the literal /opt paths are pinned textually above; this only
# moves them - and elevates through a stub that records the arguments and drops
# the root ownership an unprivileged simulation cannot grant.
with tempfile.TemporaryDirectory() as stage_text:
    stage_root = pathlib.Path(stage_text)
    frontend = stage_root / "source" / "cmd" / "jayflow" / "frontend"
    (frontend / "scripts").mkdir(parents=True)
    (stage_root / "source" / "tests").mkdir(parents=True)
    (stage_root / "candidate").mkdir()
    stage_runner = stage_root / "runner"
    stage_runner.mkdir()
    (stage_root / "source" / "tests" / "mobile-release-systemd.sh").write_text(
        "#!/usr/bin/env bash\nexit 0\n", encoding="utf-8"
    )
    (frontend / "scripts" / "mobile-release.playwright.mjs").write_text(
        "process.exit(0)\n", encoding="utf-8"
    )
    core = frontend / "node_modules" / "playwright-core"
    (core / "lib").mkdir(parents=True)
    (core / "package.json").write_text('{"name":"playwright-core"}\n', encoding="utf-8")
    (core / "lib" / "real.js").write_text("module.exports = 1\n", encoding="utf-8")
    # npm leaves links inside packages; a link staged as a link points straight
    # back under the runner home, which is the whole defect.
    (core / "lib" / "linked.js").symlink_to("real.js")
    # 0700 out of the npm cache: the chmod at the end of the step is what makes
    # this reachable at all.
    (core / "lib").chmod(0o700)
    stage_version = "2.0.33-dev"
    staged_gateway_source = stage_root / "candidate" / f"jayflow-web-{stage_version}-linux-amd64"
    staged_gateway_source.write_bytes(b"transported gateway bytes\n")
    staged_gateway_source.chmod(0o755)
    staged_daemon_source = stage_runner / "jayflowd-acceptance"
    staged_daemon_source.write_bytes(b"acceptance daemon bytes\n")
    staged_daemon_source.chmod(0o755)
    stage_bin = stage_root / "bin"
    stage_bin.mkdir()
    stage_log = stage_root / "sudo.log"
    stage_sudo = stage_bin / "sudo"
    stage_sudo.write_text(r"""#!/usr/bin/env bash
printf 'sudo %s\n' "$*" >> "$FAKE_STAGE_LOG"
ARGS=()
SKIP=0
for ARGUMENT in "$@"; do
  if [ "$SKIP" = 1 ]; then SKIP=0; continue; fi
  case "$ARGUMENT" in
    -o|-g) SKIP=1; continue ;;
  esac
  ARGS+=("$ARGUMENT")
done
# A staged copy that silently diverged from the audited byte: the step has to
# notice, because a daemon that still starts would make the acceptance green
# over a byte no release ships.
case "${FAKE_STAGE_FAILURE:-}" in
  corrupt-gateway) PATTERN='jayflow-web-' ;;
  corrupt-daemon) PATTERN='/jayflowd' ;;
  *) PATTERN='' ;;
esac
if [ -n "$PATTERN" ] && [ "${ARGS[0]}" = install ]; then
  case " $* " in
    *"$PATTERN"*)
      "${ARGS[@]}"
      printf 'x' >> "${ARGS[$((${#ARGS[@]} - 1))]}"
      exit 0
      ;;
  esac
fi
exec "${ARGS[@]}"
""", encoding="utf-8")
    stage_sudo.chmod(0o755)
    simulated_staging = stage_script.replace(
        ACCEPTANCE_ROOT, str(stage_root / "opt" / "jayflow-acceptance")
    )
    stage_env = safe_env.copy()
    stage_env.update({
        "PATH": str(stage_bin) + os.pathsep + safe_env["PATH"],
        "VERSION": stage_version,
        "RUNNER_TEMP": str(stage_runner),
        "FAKE_STAGE_LOG": str(stage_log),
    })
    result = checked(["bash", "-c", simulated_staging], cwd=stage_root, env=stage_env)
    require_success(result, "behavioral acceptance staging")
    staged = stage_root / "opt" / "jayflow-acceptance"
    for relative in (
        f"jayflow-web-{stage_version}-linux-amd64",
        "jayflowd",
        "tests/mobile-release-systemd.sh",
        "scripts/mobile-release.playwright.mjs",
        "node_modules/playwright-core/package.json",
        "node_modules/playwright-core/lib/real.js",
        "node_modules/playwright-core/lib/linked.js",
    ):
        if not (staged / relative).is_file():
            raise SystemExit(f"the staging step did not stage {relative}")
    if list(staged.rglob("*")) != [path for path in staged.rglob("*") if not path.is_symlink()]:
        raise SystemExit("the staged tree still contains a symlink back under the runner home")
    if (staged / f"jayflow-web-{stage_version}-linux-amd64").read_bytes() != staged_gateway_source.read_bytes():
        raise SystemExit("the staged gateway is not the transported byte")
    if (staged / "jayflowd").read_bytes() != staged_daemon_source.read_bytes():
        raise SystemExit("the staged daemon is not the audited byte")
    for path in staged.rglob("*"):
        mode = path.stat().st_mode & 0o7777
        if not mode & 0o004 or (path.is_dir() and not mode & 0o001):
            raise SystemExit(f"the staged {path} is not readable/traversable by the disposable user")
    for digest in (
        hashlib.sha256(staged_gateway_source.read_bytes()).hexdigest(),
        hashlib.sha256(staged_daemon_source.read_bytes()).hexdigest(),
    ):
        if digest not in result.stdout:
            raise SystemExit("the staging step did not print both staged digests")
    elevated = stage_log.read_text(encoding="utf-8")
    for required in ("install -d -m 0755 -o root -g root", "cp -RL", "chmod -R a+rX"):
        if required not in elevated:
            raise SystemExit(f"the staging step did not elevate for {required}")
    # A root that already exists is a previous run's tree, not this run's bytes.
    result = checked(["bash", "-c", simulated_staging], cwd=stage_root, env=stage_env)
    if result.returncode == 0:
        raise SystemExit("the staging step reused an acceptance root that already existed")
    for failure in ("corrupt-gateway", "corrupt-daemon"):
        shutil.rmtree(staged.parent)
        failing_env = stage_env.copy()
        failing_env["FAKE_STAGE_FAILURE"] = failure
        result = checked(["bash", "-c", simulated_staging], cwd=stage_root, env=failing_env)
        if result.returncode == 0:
            raise SystemExit(f"the staging step accepted a staged byte that diverged: {failure}")

acceptance_step = step_named(accept_steps, "Run real-systemd and Playwright acceptance")
# The harness refuses to touch anything without both opt-ins: without
# JAYFLOW_SYSTEMD_TEST=1 it prints SKIP and exits 0, and without
# JAYFLOW_DISPOSABLE_CONFIRM=YES it exits 2. Either way it never emits a gate
# line, so the opt-ins belong to the step's identity exactly like the version.
if acceptance_step.get("env") != {
    "VERSION": "${{ needs.build_linux.outputs.version }}",
    "SOURCE_SHA": "${{ needs.build_linux.outputs.source_sha }}",
    "JAYFLOW_SYSTEMD_TEST": "1",
    "JAYFLOW_DISPOSABLE_CONFIRM": "YES",
}:
    raise SystemExit("acceptance harness identity/opt-ins are not bound to build_linux")
acceptance_script = acceptance_step["run"]
# The harness is staged 0644 from a 100644 blob — it is data, not an
# executable — so it can only be started through an explicit interpreter.
# Naming the path on its own is the defect this pins shut: sudo answers
# `command not found`.
ACCEPTANCE_HARNESS = f"{ACCEPTANCE_ROOT}/tests/mobile-release-systemd.sh"
if acceptance_script.count(ACCEPTANCE_HARNESS) != 1:
    raise SystemExit("accept_linux must name the systemd harness exactly once")
if f"bash {ACCEPTANCE_HARNESS}" not in acceptance_script:
    raise SystemExit(
        "accept_linux must run the systemd harness through bash, never as a bare path"
    )
# `sudo` resets the environment, so every variable the harness reads has to be
# carried across the elevation by name: the browser it drives and both opt-ins.
ACCEPTANCE_PRESERVED = ("JAYFLOW_CHROMIUM", "JAYFLOW_SYSTEMD_TEST", "JAYFLOW_DISPOSABLE_CONFIRM")
exact_acceptance = '''sudo --preserve-env=JAYFLOW_CHROMIUM,JAYFLOW_SYSTEMD_TEST,JAYFLOW_DISPOSABLE_CONFIRM \\
  bash /opt/jayflow-acceptance/tests/mobile-release-systemd.sh \\
  --gateway "/opt/jayflow-acceptance/jayflow-web-${VERSION}-linux-amd64" \\
  --daemon /opt/jayflow-acceptance/jayflowd \\
  --version "$VERSION" \\
  --source-sha "$SOURCE_SHA" \\
  --playwright /opt/jayflow-acceptance/scripts/mobile-release.playwright.mjs'''
if exact_acceptance not in acceptance_script:
    raise SystemExit("accept_linux does not invoke the exact transported-byte systemd harness")
# Nothing below the runner home may reach the harness. The disposable user is
# not in the runner group and /home/runner is 0750, so a $RUNNER_TEMP, $PWD or
# $GITHUB_WORKSPACE path in the fixture unit or in the Playwright invocation is
# an EACCES for the very user the harness runs everything as.
acceptance_lines = acceptance_script.splitlines()
invocation_start = [
    index for index, line in enumerate(acceptance_lines)
    if line.strip().startswith("sudo --preserve-env=")
]
invocation_end = [index for index, line in enumerate(acceptance_lines) if "| tee " in line]
if len(invocation_start) != 1 or len(invocation_end) != 1 or invocation_end[0] <= invocation_start[0]:
    raise SystemExit("accept_linux must invoke the harness exactly once, transcript piped to tee")
harness_invocation = "\n".join(acceptance_lines[invocation_start[0]:invocation_end[0]])
for forbidden in (
    "$HOME", "${HOME", "$RUNNER_TEMP", "${RUNNER_TEMP",
    "$GITHUB_WORKSPACE", "${GITHUB_WORKSPACE", "$PWD", "${PWD",
    "candidate/", "source/",
):
    if forbidden in harness_invocation:
        raise SystemExit(
            f"the harness must not be handed a path the disposable user cannot traverse: {forbidden}"
        )
harness_paths = re.findall(r"(?:bash|--gateway|--daemon|--playwright)\s+\"?(/[^\"\s\\]+)", harness_invocation)
if len(harness_paths) != 4:
    raise SystemExit(f"the harness invocation names {harness_paths}, want four absolute staged paths")
for path in harness_paths:
    if not path.startswith(ACCEPTANCE_ROOT + "/"):
        raise SystemExit(f"the harness is handed {path}, which is not under {ACCEPTANCE_ROOT}")
preserve_flags = re.findall(r"--preserve-env=(\S+)", acceptance_script)
if len(preserve_flags) != 1:
    raise SystemExit("accept_linux must elevate the harness exactly once, with one --preserve-env")
preserved_names = preserve_flags[0].split(",")
if preserved_names != list(ACCEPTANCE_PRESERVED):
    raise SystemExit(
        f"accept_linux preserves {preserved_names} across sudo, want {list(ACCEPTANCE_PRESERVED)}"
    )
# The harness reports through the pipe, so without pipefail a harness that dies
# would be laundered into the exit status of `tee`.
if "set -euo pipefail" not in acceptance_script:
    raise SystemExit("accept_linux must run the acceptance under set -euo pipefail")
if "| tee " not in acceptance_script:
    raise SystemExit("accept_linux must keep the acceptance transcript for the gate scan")
acceptance_passes = [
    "playwright: 390x844 layout PASS",
    "playwright: secure session and headers PASS",
    "playwright: websocket origin/token/limit PASS",
    "playwright: real PTY and replay PASS",
    "playwright: redaction PASS",
    "mobile-release playwright: PASS",
    "mobile-release systemd rollback: PASS",
    "mobile-release systemd: PASS",
]
for gate in acceptance_passes:
    if gate not in acceptance_script:
        raise SystemExit(f"accept_linux does not require successful gate output: {gate}")
# All eight, in the planned order, and nothing else: a shortened list is a
# silently weakened acceptance.
exact_required_gates = "REQUIRED_GATES=(\n" + "".join(
    f'  "{gate}"\n' for gate in acceptance_passes
) + ")"
if exact_required_gates not in acceptance_script:
    raise SystemExit("accept_linux REQUIRED_GATES is not exactly the eight planned gate lines")

with tempfile.TemporaryDirectory() as accept_temp_text:
    accept_temp = pathlib.Path(accept_temp_text)
    (accept_temp / "candidate").mkdir()
    (accept_temp / "source" / "tests").mkdir(parents=True)
    (accept_temp / "source" / "cmd" / "jayflow" / "frontend" / "scripts").mkdir(parents=True)
    gateway = accept_temp / "candidate" / "jayflow-web-2.0.33-dev-linux-amd64"
    gateway.write_text("fixture", encoding="utf-8")
    fake_bin = accept_temp / "fake-bin"
    fake_bin.mkdir()
    accept_log = accept_temp / "tools.log"
    for tool_name in ("systemctl", "loginctl", "runuser", "useradd", "userdel", "chromium"):
        stub = fake_bin / tool_name
        stub.write_text(r'''#!/usr/bin/env bash
printf '%s %s\n' "$(basename "$0")" "$*" >> "$FAKE_ACCEPT_TOOL_LOG"
[ "${FAKE_ACCEPT_FAILURE:-}" != "service start" ] || exit 42
exit 0
''', encoding="utf-8")
        stub.chmod(0o755)
    staged_accept_root = accept_temp / "opt" / "jayflow-acceptance"
    (staged_accept_root / "tests").mkdir(parents=True)
    harness = staged_accept_root / "tests" / "mobile-release-systemd.sh"
    harness.write_text(r'''#!/usr/bin/env bash
set -euo pipefail
printf 'harness %s\n' "$*" >> "$FAKE_ACCEPT_TOOL_LOG"
# Same two opt-in guards as the real harness, with the same outcomes: no
# JAYFLOW_SYSTEMD_TEST is a silent SKIP that exits 0, and no
# JAYFLOW_DISPOSABLE_CONFIRM is a refusal. Neither prints a gate line.
if [ "${JAYFLOW_SYSTEMD_TEST:-}" != "1" ]; then
  printf '%s\n' 'SKIP: set JAYFLOW_SYSTEMD_TEST=1 on a disposable Linux/amd64 user-systemd VM'
  exit 0
fi
if [ "${JAYFLOW_DISPOSABLE_CONFIRM:-}" != "YES" ]; then
  printf '%s\n' 'FAIL: set JAYFLOW_DISPOSABLE_CONFIRM=YES only on the disposable target' >&2
  exit 2
fi
systemctl --user start jayflow-web.service
loginctl enable-linger fixture
runuser -u fixture -- true
useradd fixture
userdel fixture
"$JAYFLOW_CHROMIUM" --version
case "${FAKE_ACCEPT_FAILURE:-}" in
  "") ;;
  late-exit) ;;
  *PASS) ;;
  *) exit 42 ;;
esac
for GATE in \
  'playwright: 390x844 layout PASS' \
  'playwright: secure session and headers PASS' \
  'playwright: websocket origin/token/limit PASS' \
  'playwright: real PTY and replay PASS' \
  'playwright: redaction PASS' \
  'mobile-release playwright: PASS' \
  'mobile-release systemd rollback: PASS' \
  'mobile-release systemd: PASS'; do
  [ "$GATE" = "${FAKE_ACCEPT_FAILURE:-}" ] || printf '%s\n' "$GATE"
done
# Every gate printed and then a hard failure: only pipefail can see this one,
# because `tee` succeeded.
[ "${FAKE_ACCEPT_FAILURE:-}" != late-exit ] || exit 42
''', encoding="utf-8")
    # 100644, exactly as `git ls-tree` reports it in the private source, so a
    # bare-path invocation cannot succeed here either.
    harness.chmod(0o644)
    fake_sudo = fake_bin / "sudo"
    fake_sudo.write_text(r'''#!/usr/bin/env bash
printf 'sudo %s\n' "$*" >> "$FAKE_ACCEPT_TOOL_LOG"
case "${1:-}" in
  --preserve-env=*) PRESERVED=",${1#--preserve-env=}," ;;
  *) exit 64 ;;
esac
shift
# Real sudo resets the environment: anything the caller did not list by name is
# simply not there on the other side of the elevation.
for NAME in JAYFLOW_CHROMIUM JAYFLOW_SYSTEMD_TEST JAYFLOW_DISPOSABLE_CONFIRM; do
  case "$PRESERVED" in
    *",$NAME,"*) ;;
    *) unset "$NAME" ;;
  esac
done
exec "$@"
''', encoding="utf-8")
    fake_sudo.chmod(0o755)
    accept_env = safe_env.copy()
    accept_env.update({
        "PATH": str(fake_bin) + os.pathsep + safe_env["PATH"],
        "VERSION": "2.0.33-dev",
        "SOURCE_SHA": "0123456789abcdef0123456789abcdef01234567",
        "PUBLIC_KEY": "dGVzdC1wdWJsaWMta2V5",
        "RUNNER_TEMP": str(accept_temp / "runner"),
        "JAYFLOW_CHROMIUM": str(fake_bin / "chromium"),
        "JAYFLOW_SYSTEMD_TEST": acceptance_step["env"]["JAYFLOW_SYSTEMD_TEST"],
        "JAYFLOW_DISPOSABLE_CONFIRM": acceptance_step["env"]["JAYFLOW_DISPOSABLE_CONFIRM"],
        "FAKE_ACCEPT_TOOL_LOG": str(accept_log),
    })
    pathlib.Path(accept_env["RUNNER_TEMP"]).mkdir()
    accept_auditor = pathlib.Path(accept_env["RUNNER_TEMP"]) / "jayflow-release-tool"
    accept_auditor.write_text(r'''#!/usr/bin/env bash
printf 'audit %s\n' "$*" >> "$FAKE_ACCEPT_TOOL_LOG"
[ "${FAKE_ACCEPT_FAILURE:-}" != audit ] || exit 42
exit 0
''', encoding="utf-8")
    accept_auditor.chmod(0o755)
    result = checked(["bash", "-c", accept_audit["run"]], cwd=accept_temp, env=accept_env)
    require_success(result, "behavioral transported Linux audit")
    audit_failure_env = accept_env.copy()
    audit_failure_env["FAKE_ACCEPT_FAILURE"] = "audit"
    result = checked(["bash", "-c", accept_audit["run"]], cwd=accept_temp, env=audit_failure_env)
    if result.returncode == 0:
        raise SystemExit("accept_linux accepted injected static audit failure")
    # Same relocation as the staging simulation: only the absolute prefix moves.
    simulated_acceptance = acceptance_script.replace(ACCEPTANCE_ROOT, str(staged_accept_root))
    result = checked(["bash", "-c", simulated_acceptance], cwd=accept_temp, env=accept_env)
    require_success(result, "behavioral Linux systemd/Playwright acceptance")
    observed_tools = accept_log.read_text(encoding="utf-8")
    for required in ("sudo ", "harness ", "systemctl ", "loginctl ", "runuser ", "useradd ", "userdel ", "chromium "):
        if required not in observed_tools:
            raise SystemExit(f"acceptance simulator did not exercise stub {required.strip()}")
    for failure in (
        "service start", "health", "late-exit",
        "playwright: 390x844 layout PASS",
        "playwright: secure session and headers PASS",
        "playwright: websocket origin/token/limit PASS",
        "playwright: real PTY and replay PASS",
        "playwright: redaction PASS",
        "mobile-release playwright: PASS",
        "mobile-release systemd rollback: PASS",
        "mobile-release systemd: PASS",
    ):
        failing_env = accept_env.copy()
        failing_env["FAKE_ACCEPT_FAILURE"] = failure
        result = checked(["bash", "-c", simulated_acceptance], cwd=accept_temp, env=failing_env)
        if result.returncode == 0:
            raise SystemExit(f"accept_linux accepted injected failure {failure}")


def elevations_in(script):
    """Every command in `script` that reaches for root, comments excluded."""
    found = []
    for line in script.splitlines():
        if line.strip().startswith("#"):
            continue
        for match in re.finditer(r"sudo\b[^\n]*", line):
            found.append(match.group(0).strip().rstrip("\\").strip())
    return found


# The sudo audit that follows is scoped to one script, so the job's step list is
# closed here: an extra step appended anywhere in accept_linux would otherwise
# be free to elevate for whatever it liked, and require_order alone tolerates
# unlisted steps.
ACCEPT_STEP_NAMES = (
    "Check out public release tooling",
    "Check out the private source from the Linux build",
    "Verify accepted source identity",
    "Set up Go from the accepted source go.mod",
    "Build the trusted public auditor",
    "Download the transported Linux gateway",
    "Build the acceptance daemon",
    "Audit transported Linux bytes",
    "Set up Node.js",
    "Expose the runner browser as Chromium",
    "Install acceptance frontend dependencies",
    ACCEPT_STAGE_STEP_NAME,
    "Run real-systemd and Playwright acceptance",
    ACCEPT_DIAGNOSTICS_STEP_NAME,
)
if tuple(names(accept_steps)) != ACCEPT_STEP_NAMES:
    raise SystemExit(
        f"accept_linux steps are {names(accept_steps)}, want exactly {list(ACCEPT_STEP_NAMES)}"
    )
# And every elevation in the whole job is pinned by name and by target: the
# seven writes that stage the acceptance inputs where the disposable user can
# reach them, the symlink that exposes the runner's browser, the harness itself,
# and the two journal reads of the diagnostics.
ACCEPT_ELEVATIONS = (
    # Staging the acceptance inputs on a filesystem the disposable user can
    # traverse: one directory tree, four files, one package, one opening chmod.
    "sudo install -d -m 0755 -o root -g root",
    "sudo install -m 0755 -o root -g root",
    "sudo install -m 0755 -o root -g root",
    "sudo install -m 0644 -o root -g root",
    "sudo install -m 0644 -o root -g root",
    "sudo cp -RL",
    'sudo chmod -R a+rX "$ACCEPTANCE_ROOT"',
    'sudo ln -sfn -- "$CHROMIUM_SOURCE" /usr/bin/chromium',
    "sudo --preserve-env=JAYFLOW_CHROMIUM,JAYFLOW_SYSTEMD_TEST,JAYFLOW_DISPOSABLE_CONFIRM",
    "sudo journalctl --no-pager -o short-iso --since '-30 min'",
    "sudo journalctl --no-pager -o short-iso --since '-30 min' _COMM=jayflowd _COMM=jayflow-web _COMM=systemd",
)
accept_elevations = [
    elevation for step in accept_steps for elevation in elevations_in(step.get("run", ""))
]
if sorted(accept_elevations) != sorted(ACCEPT_ELEVATIONS):
    raise SystemExit(
        f"accept_linux elevates for {sorted(accept_elevations)}, want exactly {sorted(ACCEPT_ELEVATIONS)}"
    )

# ---- failure-only acceptance diagnostics -----------------------------------
# The harness removes the disposable user and both units in its trap, so when
# the acceptance dies with "the daemon fixture did not become active" the runner
# state that would name the cause is already gone by the time the job ends. The
# system journal is the one witness that outlives the userdel, and nothing in
# this job collects it. This step is that collection, and it is deliberately
# inert on a green run: it reads, it never writes, it never leaves the runner,
# and it can only run after the acceptance has already failed.
diagnostics_step = step_named(accept_steps, ACCEPT_DIAGNOSTICS_STEP_NAME)
if accept_steps.index(diagnostics_step) != accept_steps.index(acceptance_step) + 1:
    raise SystemExit(
        "acceptance diagnostics must be the step immediately after the acceptance itself"
    )
# `if: failure()` and nothing weaker: on a green run this step must not add a
# single line, and a diagnostics step that ran unconditionally would also run
# before the transcript it is meant to explain even exists.
if diagnostics_step.get("if") != "failure()":
    raise SystemExit("acceptance diagnostics must run only with if: failure()")
if "uses" in diagnostics_step:
    raise SystemExit(
        "acceptance diagnostics must be a plain run step: no action, and above all no upload"
    )
# No env of its own is the strongest available statement that no secret is in
# scope: RUNNER_TEMP already comes from the runner. The job holds only the
# read-only deploy key, pinned to its private checkout, and the job permissions
# stay contents: read (asserted with the other read-only jobs above).
if "env" in diagnostics_step:
    raise SystemExit("acceptance diagnostics must not introduce environment of its own")
if "working-directory" in diagnostics_step:
    raise SystemExit("acceptance diagnostics must not run inside the private source checkout")
diagnostics_text = serialized(diagnostics_step)
if re.search(r"secrets\.|vars\.|JAYFLOW_SOURCE_DEPLOY_KEY|JAYFLOW_RELEASE_PRIVATE_KEY", diagnostics_text):
    raise SystemExit("acceptance diagnostics must not reach for any secret or repository variable")
# A gate that is allowed to fail is not a gate, and a diagnostics step that is
# allowed to fail would hide the very truncation it exists to prevent.
for step in accept_steps:
    if "continue-on-error" in step:
        raise SystemExit(
            f"accept_linux/{step.get('name')!r} must not be allowed to fail silently: continue-on-error"
        )
diagnostics_script = diagnostics_step["run"]
# Read-only and offline: the diagnosis is printed into the job log, never
# uploaded, never sent anywhere, and nothing on the runner is modified.
for forbidden in (
    "curl ", "wget ", "ssh ", "scp ", "nc -", "http://", "https://",
    "gh api", "gh release", "gh run", "upload-artifact",
    "rm -", "chmod ", "chown ", "mkdir ", "systemctl start", "systemctl stop",
    "userdel", "useradd", ">>", "tee ",
):
    if forbidden in diagnostics_script:
        raise SystemExit(f"acceptance diagnostics must only read and print, found: {forbidden}")
# Two elevations, and only for the system journal: it is the only fact here
# that an unprivileged read cannot reach. The first read is keyword-filtered
# across the whole journal, the second is the units' own _COMM.
DIAGNOSTICS_JOURNAL = "sudo journalctl --no-pager -o short-iso --since '-30 min'"
DIAGNOSTICS_UNIT_JOURNAL = (
    "sudo journalctl --no-pager -o short-iso --since '-30 min' "
    "_COMM=jayflowd _COMM=jayflow-web _COMM=systemd"
)
elevations = elevations_in(diagnostics_script)
if elevations != [DIAGNOSTICS_JOURNAL, DIAGNOSTICS_UNIT_JOURNAL]:
    raise SystemExit(
        "acceptance diagnostics may elevate only for the two journal reads "
        f"{[DIAGNOSTICS_JOURNAL, DIAGNOSTICS_UNIT_JOURNAL]!r}, found {elevations}"
    )
# Both journal reads are tolerated, and the tolerance carries the comment that
# says why: a bare `|| true` next to a diagnostic is how a real refusal becomes
# invisible later.
for journal_read in (DIAGNOSTICS_JOURNAL, DIAGNOSTICS_UNIT_JOURNAL):
    positions = [
        index for index, line in enumerate(diagnostics_script.splitlines())
        if line.strip().rstrip("\\").strip() == journal_read
    ]
    if len(positions) != 1:
        raise SystemExit(f"acceptance diagnostics must read {journal_read!r} exactly once")
    lines = diagnostics_script.splitlines()
    tail = "\n".join(lines[positions[0]:positions[0] + 5])
    if "|| true" not in tail:
        raise SystemExit(f"the journal read {journal_read!r} must be tolerated with || true")
    if not any(
        lines[index].strip().startswith("#")
        for index in range(max(0, positions[0] - 8), positions[0])
    ):
        raise SystemExit(f"the tolerated journal read {journal_read!r} must carry the comment that says why")
for required in (
    'ACCEPTANCE_LOG="$RUNNER_TEMP/mobile-release-acceptance.log"',
    'cat "$ACCEPTANCE_LOG"',
    DIAGNOSTICS_JOURNAL,
    # R18 collected nothing usable: the harness calls `runuser` hundreds of
    # times and every call writes two pam_unix session lines, which matched
    # `failed`-free but matched `jfrel`, so `tail` kept only session noise. The
    # two pam facilities are dropped before the include filter runs.
    "grep -Ev 'pam_unix\\(runuser|pam_unix\\(systemd-user'",
    "grep -E 'jayflowd|jayflow-web|jfrel|user@|Failed|failed|denied'",
    "tail -n 400",
    # And the units themselves, straight from their own _COMM, so a fixture
    # that never execed is visible even if its message matches no keyword.
    DIAGNOSTICS_UNIT_JOURNAL,
    "grep -E 'jfrel|jayflow|Failed|denied'",
    "loginctl list-users --no-legend",
    "ls -la /run/user",
    "systemctl --version | head -1",
    "cat /etc/os-release | head -3",
    "uname -r",
) + ACCEPT_DIAGNOSTICS_LAYOUT_LINES:
    if required not in diagnostics_script:
        raise SystemExit(f"acceptance diagnostics does not collect: {required}")
# `id` on a line of its own: which user the elevated harness actually ran as.
if not re.search(r"(?m)^\s*id\s*$", diagnostics_script):
    raise SystemExit("acceptance diagnostics must print id on a line of its own")
# Neither userns key is guaranteed to exist on the runner image, and a missing
# key is not itself the diagnosis, so the read is explicitly tolerated - and the
# tolerance carries the comment that says why, because a bare `|| true` next to
# a sysctl is exactly how a real failure gets swallowed by accident later.
DIAGNOSTICS_SYSCTL = (
    "sysctl kernel.apparmor_restrict_unprivileged_userns kernel.unprivileged_userns_clone || true"
)
diagnostics_lines = diagnostics_script.splitlines()
sysctl_positions = [
    index for index, line in enumerate(diagnostics_lines) if line.strip() == DIAGNOSTICS_SYSCTL
]
if len(sysctl_positions) != 1:
    raise SystemExit(
        "acceptance diagnostics must read both userns keys exactly once, tolerated with || true"
    )
if not any(
    diagnostics_lines[index].strip().startswith("#")
    for index in range(max(0, sysctl_positions[0] - 3), sysctl_positions[0])
):
    raise SystemExit("the tolerated userns sysctl read must carry the comment that says why")
# Behavioural: the step exists to print everything, so it must survive every
# probe that legitimately fails on a runner - a filter that matches nothing, an
# absent sysctl key, a journal it is refused - and it must still print the
# transcript and reach the last probe. A `set -e` abort halfway through is the
# failure mode this catches.
with tempfile.TemporaryDirectory() as diag_text:
    diag_root = pathlib.Path(diag_text)
    diag_bin = diag_root / "bin"
    diag_bin.mkdir()
    for tool_name, body in (
        # A journal with no matching line at all: the grep filter exits 1.
        ("journalctl", "printf 'unrelated runner chatter\\n'\nexit 0\n"),
        ("loginctl", "exit 1\n"),
        # Neither key present, exactly like a kernel without the Ubuntu patch.
        ("sysctl", "printf 'sysctl: cannot stat %s\\n' \"$*\" >&2\nexit 255\n"),
        ("systemctl", "printf 'systemd 255 (255.4)\\nmore\\nlines\\n'\n"),
        ("mount", "printf 'proc on /proc type proc (rw)\\n'\n"),
    ):
        stub = diag_bin / tool_name
        stub.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
        stub.chmod(0o755)
    # The elevation must also tolerate a journal it is refused.
    sudo_stub = diag_bin / "sudo"
    sudo_stub.write_text(
        "#!/usr/bin/env bash\n"
        '[ "${FAKE_DIAG_JOURNAL:-}" != refused ] || exit 1\n'
        'exec "$@"\n',
        encoding="utf-8",
    )
    sudo_stub.chmod(0o755)
    diag_env = safe_env.copy()
    diag_env["PATH"] = str(diag_bin) + os.pathsep + safe_env["PATH"]
    diag_env["RUNNER_TEMP"] = str(diag_root / "runner")
    pathlib.Path(diag_env["RUNNER_TEMP"]).mkdir()
    transcript = pathlib.Path(diag_env["RUNNER_TEMP"]) / "mobile-release-acceptance.log"
    transcript.write_text(
        "mobile-release-systemd: the daemon fixture did not become active\n", encoding="utf-8"
    )
    result = checked(["bash", "-c", diagnostics_script], cwd=diag_root, env=diag_env)
    require_success(result, "behavioral acceptance diagnostics")
    if "the daemon fixture did not become active" not in result.stdout:
        raise SystemExit("acceptance diagnostics did not print the acceptance transcript")
    # The last probe of the step, so its output proves nothing aborted earlier.
    if "ID=" not in result.stdout:
        raise SystemExit("acceptance diagnostics stopped before printing /etc/os-release")
    # `if: failure()` also fires when a step before the acceptance failed, so
    # there may be no transcript at all: that must be reported, not fatal.
    transcript.unlink()
    refused_env = diag_env.copy()
    refused_env["FAKE_DIAG_JOURNAL"] = "refused"
    result = checked(["bash", "-c", diagnostics_script], cwd=diag_root, env=refused_env)
    require_success(result, "behavioral acceptance diagnostics without a transcript")
    if "mobile-release-acceptance.log" not in result.stdout:
        raise SystemExit("acceptance diagnostics must name the transcript it could not find")

nsis_install = scripts["Install NSIS and expose the runner browser as Chromium"]
for required in (
    "NSIS_PACKAGE_VERSION=3.09-4ubuntu1",
    '"nsis=$NSIS_PACKAGE_VERSION"',
    "dpkg-query",
    "makensis -VERSION",
):
    if required not in nsis_install:
        raise SystemExit(f"NSIS installation is not version-pinned/fail-closed: {required}")

stage_script = scripts["Stage and audit the exact unsigned release assets"]
for required in (
    "${#INSTALLERS[@]}",
    "-amd64-installer.exe",
    "ACTUAL_ASSETS",
    "EXPECTED_ASSETS",
    "windows_file_version=%s",
    "install_scope=user",
    "%LOCALAPPDATA%",
    "audit-windows",
    '-daemon cmd/jayflow/embedded/jayflowd',
    '-source-ref "$SOURCE_REF"',
    '-source-sha "$SOURCE_SHA"',
    "dist-windows",
):
    if required not in stage_script:
        raise SystemExit(f"output staging/audit is missing {required}")
windows_allowlist = '''EXPECTED_ASSETS=(
  "JayFlow-${VERSION}-setup.exe"
  "JayFlow-${VERSION}.exe"
  JayFlow-setup.exe
  buildinfo.txt
)'''
if windows_allowlist not in stage_script:
    raise SystemExit("the staged Windows allow-list must remain exactly the original four unsigned names")

downloaded_audit = scripts["Audit downloaded bytes before signing"]
for required in (
    '-daemon internal-daemon/jayflowd',
    '-source-ref "$SOURCE_REF"',
    '-source-sha "$SOURCE_SHA"',
    "audit-linux",
    'linux-dist/jayflow-web-${VERSION}-linux-amd64',
    'cp "linux-dist/jayflow-web-${VERSION}-linux-amd64" dist/',
    "UNSIGNED_ASSETS",
):
    if required not in downloaded_audit:
        raise SystemExit(f"pre-secret downloaded audit is missing {required}")
if not (
    downloaded_audit.index("audit-windows")
    < downloaded_audit.index("audit-linux")
    < downloaded_audit.index('cp "linux-dist/jayflow-web-${VERSION}-linux-amd64" dist/')
    < downloaded_audit.index("EXPECTED_UNSIGNED_ASSETS=(")
):
    raise SystemExit("the Linux ELF may enter dist/ only after the Windows, daemon, and Linux audits")
downloaded_audit_env = step_named(sign_steps, "Audit downloaded bytes before signing").get("env", {})
if downloaded_audit_env.get("SOURCE_REF") != "${{ needs.build_windows.outputs.ref }}":
    raise SystemExit("sign_publish audit source ref is not tied to build output")
if downloaded_audit_env.get("SOURCE_SHA") != "${{ needs.build_windows.outputs.source_sha }}":
    raise SystemExit("sign_publish audit source SHA is not tied to build output")

generated_audit = scripts["Audit Wails-generated changes"]
for required in (
    'REPO_ROOT="$(git rev-parse --show-toplevel)"',
    "git restore --worktree -- cmd/jayflow/wails.json",
    "git diff --check",
    "git diff --exit-code",
    "git ls-files --others --exclude-standard -z",
):
    if required not in generated_audit:
        raise SystemExit(f"generated-change audit is missing {required}")

publish_script = scripts["Create or reconcile the atomic public release"]
for required in (
    "MIN_GH_VERSION=2.45.0",
    "gh --version",
    "gh release view",
    "gh release create",
    "gh release upload",
    "gh release download",
    "gh release edit",
    "require_exact_assets",
    "reject_unexpected_assets",
    "verify-bundle",
    "cmp -s",
    "--draft",
    "--latest",
    "--clobber",
):
    if required not in publish_script:
        raise SystemExit(f"publication logic is missing {required}")
if "release delete" in workflow_text:
    raise SystemExit("release deletion is forbidden")
for required in (
    '"jayflow-web-${VERSION}-linux-amd64"',
    "linux-latest.json",
    "NON_CHANNEL_ASSETS=(",
    'LINUX_URL="https://github.com/julubileu/jayflow-releases/releases/download/${TAG}/jayflow-web-${VERSION}-linux-amd64"',
    '-linux-url "$LINUX_URL"',
    'REMOTE_VERIFY_DIR="$(mktemp -d)"',
):
    if required not in publish_script:
        raise SystemExit(f"ten-asset publication is missing {required}")
if publish_script.count("verify-bundle") != 2:
    raise SystemExit("both the immutable public path and the draft path must run verify-bundle")
non_channel_body = publish_script.split("NON_CHANNEL_ASSETS=(", 1)[1].split("\n          )", 1)[0]
if len(re.findall(r"^[ \t]+(?:\"?dist/)", non_channel_body, re.MULTILINE)) != 8:
    raise SystemExit("NON_CHANNEL_ASSETS must contain exactly eight assets")
expected_assets_block = '''EXPECTED_ASSETS=(
  "JayFlow-${VERSION}.exe"
  "JayFlow-${VERSION}-setup.exe"
  JayFlow-setup.exe
  buildinfo.txt
  release-manifest.json
  release-manifest.sig
  checksums.txt
  latest.json
  "jayflow-web-${VERSION}-linux-amd64"
  linux-latest.json
)'''
if expected_assets_block not in publish_script:
    raise SystemExit("EXPECTED_ASSETS must keep the original eight entries first and append the two Linux names")
first_upload = publish_script.index('gh release upload "$TAG" "${NON_CHANNEL_ASSETS[@]}"')
latest_upload = publish_script.index('gh release upload "$TAG" dist/latest.json')
linux_latest_upload = publish_script.index('gh release upload "$TAG" dist/linux-latest.json')
final_view = publish_script.index("read_release", linux_latest_upload)
remote_download = publish_script.index('gh release download "$TAG"', final_view)
final_edit = publish_script.rindex('gh release edit "$TAG"')
if not first_upload < latest_upload < linux_latest_upload < final_view < remote_download < final_edit:
    raise SystemExit("atomic common/Windows/Linux/verify/public order is wrong")

sign_bundle_script = scripts["Sign final bytes and generate authenticated metadata"]
verify_bundle_script = scripts["Verify signed final bundle without the private key"]
for label, script in (("sign", sign_bundle_script), ("verify", verify_bundle_script)):
    for required in (
        'WINDOWS_URL="https://github.com/julubileu/jayflow-releases/releases/download/v${VERSION}/JayFlow-${VERSION}.exe"',
        'LINUX_URL="https://github.com/julubileu/jayflow-releases/releases/download/v${VERSION}/jayflow-web-${VERSION}-linux-amd64"',
        '-portable-url "$WINDOWS_URL"',
        '-linux-url "$LINUX_URL"',
    ):
        if required not in script:
            raise SystemExit(f"{label}-bundle channel binding is missing {required}")
exact_sign_invocation = '''"$RUNNER_TEMP/jayflow-release-tool" sign-bundle \\
  -version "$VERSION" \\
  -dir dist \\
  -portable-url "$WINDOWS_URL" \\
  -linux-url "$LINUX_URL"'''
if not sign_bundle_script.rstrip().endswith(exact_sign_invocation):
    raise SystemExit("the secret-bearing step must end with exactly the audited sign-bundle invocation")
if "unset JAYFLOW_RELEASE_PRIVATE_KEY" not in verify_bundle_script:
    raise SystemExit("the verification step must unset the private key before verifying")
if '-public-key "$PUBLIC_KEY"' not in verify_bundle_script:
    raise SystemExit("verify-bundle must re-check both channels against the derived public key")

with tempfile.TemporaryDirectory() as temp_dir_text:
    temp_dir = pathlib.Path(temp_dir_text)
    tool = temp_dir / "jayflow-release-tool"
    result = checked(["go", "build", "-trimpath", "-o", str(tool), "./cmd/release-tool"])
    require_success(result, "building trusted release tool")

    vector_private = base64.b64encode(bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60" +
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )).decode()
    key_env = safe_env.copy()
    key_env["JAYFLOW_RELEASE_PRIVATE_KEY"] = vector_private
    public_result = checked([str(tool), "pubkey"], env=key_env)
    require_success(public_result, "deriving vector public key")
    vector_public = public_result.stdout.strip()

    compatibility = temp_dir / "compatibility"
    compatibility.mkdir()
    version = "2.0.33-dev"
    for name, body in {
        f"JayFlow-{version}.exe": b"portable compatibility bytes\n",
        f"JayFlow-{version}-setup.exe": b"installer compatibility bytes\n",
        "JayFlow-setup.exe": b"installer compatibility bytes\n",
        "buildinfo.txt": b"compatibility metadata\n",
        f"jayflow-web-{version}-linux-amd64": b"linux gateway compatibility bytes\n",
    }.items():
        (compatibility / name).write_bytes(body)
    portable_url = (
        "https://github.com/julubileu/jayflow-releases/releases/download/"
        f"v{version}/JayFlow-{version}.exe"
    )
    linux_url = (
        "https://github.com/julubileu/jayflow-releases/releases/download/"
        f"v{version}/jayflow-web-{version}-linux-amd64"
    )
    result = checked([
        str(tool), "sign-bundle", "-version", version, "-dir", str(compatibility),
        "-portable-url", portable_url, "-linux-url", linux_url,
    ], env=key_env)
    require_success(result, "public signer compatibility fixture")
    source_latest = temp_dir / "source-latest.json"
    result = checked([
        "go", "run", "./internal/updater/signtool",
        "-version", version,
        "-artifact", str(compatibility / f"JayFlow-{version}.exe"),
        "-url", portable_url,
        "-out", str(source_latest),
    ], cwd=source_repo, env=key_env)
    require_success(result, "private source signer/verifier compatibility")
    if source_latest.read_bytes() != (compatibility / "latest.json").read_bytes():
        raise SystemExit("public signer latest.json differs byte-for-byte from private source signtool")

    fake_gh = temp_dir / "gh"
    fake_gh.write_text(r'''#!/usr/bin/env python3
import json
import os
import pathlib
import shutil
import sys

args = sys.argv[1:]
with pathlib.Path(os.environ["FAKE_GH_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(args) + "\n")
if args == ["--version"]:
    print("gh version 2.45.0 (validator fake)")
    raise SystemExit(0)

state_path = pathlib.Path(os.environ["FAKE_GH_STATE"])
state = json.loads(state_path.read_text(encoding="utf-8"))
failure = os.environ.get("FAKE_GH_FAIL", "")
remote = pathlib.Path(os.environ["FAKE_GH_REMOTE"])

def fail_if(point):
    if failure == point:
        print("injected gh failure: " + point, file=sys.stderr)
        raise SystemExit(42)

if args[:2] == ["release", "view"]:
    state["views"] = state.get("views", 0) + 1
    state_path.write_text(json.dumps(state), encoding="utf-8")
    if failure == "final-view" and state["views"] >= 2:
        fail_if("final-view")
    if not state["exists"]:
        print("release not found", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps({"isDraft": state["draft"], "assets": [{"name": name} for name in state["assets"]]}))
elif args[:2] == ["release", "create"]:
    fail_if("create")
    state.update({"exists": True, "draft": True, "assets": []})
    state_path.write_text(json.dumps(state), encoding="utf-8")
elif args[:2] == ["release", "upload"]:
    repo_index = args.index("--repo")
    names = [pathlib.Path(value).name for value in args[3:repo_index]]
    point = "upload-common"
    if names == ["latest.json"]: point = "upload-windows-latest"
    if names == ["linux-latest.json"]: point = "upload-linux-latest"
    fail_if(point)
    for value in args[3:repo_index]:
        source = pathlib.Path(value)
        name = pathlib.Path(value).name
        shutil.copyfile(source, remote / name)
        if name not in state["assets"]:
            state["assets"].append(name)
    if failure == "premature-public" and point == "upload-linux-latest":
        state["draft"] = False
    state_path.write_text(json.dumps(state), encoding="utf-8")
elif args[:2] == ["release", "download"]:
    fail_if("download")
    destination = pathlib.Path(args[args.index("--dir") + 1])
    destination.mkdir(parents=True, exist_ok=True)
    for name in state["assets"]:
        shutil.copyfile(remote / name, destination / name)
    if failure == "remote-verify":
        with (destination / "linux-latest.json").open("ab") as handle:
            handle.write(b"tampered after remote download")
elif args[:2] == ["release", "edit"]:
    fail_if("edit-final")
    state["draft"] = False
    state_path.write_text(json.dumps(state), encoding="utf-8")
else:
    raise SystemExit("unsupported fake gh invocation: " + repr(args))
''', encoding="utf-8")
    fake_gh.chmod(0o755)

    expected_assets = [
        f"JayFlow-{version}.exe",
        f"JayFlow-{version}-setup.exe",
        "JayFlow-setup.exe",
        "buildinfo.txt",
        "release-manifest.json",
        "release-manifest.sig",
        "checksums.txt",
        "latest.json",
        f"jayflow-web-{version}-linux-amd64",
        "linux-latest.json",
    ]

    def publication_scenario(scenario, should_pass, *, initial=None, failure=""):
        scenario_root = temp_dir / scenario
        scenario_root.mkdir()
        dist = scenario_root / "dist"
        shutil.copytree(compatibility, dist)
        remote = scenario_root / "remote"
        remote.mkdir()
        initial = initial or scenario
        exists = initial != "absent"
        draft = initial.startswith("draft")
        assets = []
        if initial == "draft-partial-common":
            assets = expected_assets[:3]
        elif initial == "draft-with-windows-latest":
            assets = expected_assets[:8]
        elif initial == "draft-complete":
            assets = expected_assets.copy()
        if initial == "draft-extra":
            assets = [expected_assets[0], "unexpected.bin"]
        elif initial == "published-missing-linux":
            assets = [name for name in expected_assets if not name.startswith("jayflow-web-")]
        elif initial == "published-extra":
            assets = expected_assets + ["unexpected.bin"]
        elif initial.startswith("published"):
            assets = expected_assets.copy()
        for name in assets:
            source = compatibility / name
            if source.is_file():
                shutil.copyfile(source, remote / name)
            elif name == "unexpected.bin":
                (remote / name).write_bytes(b"unexpected")
        if initial == "published-different-linux":
            with (remote / f"jayflow-web-{version}-linux-amd64").open("ab") as handle:
                handle.write(b"different")
        state = scenario_root / "state.json"
        state.write_text(json.dumps({"exists": exists, "draft": draft, "assets": assets, "views": 0}), encoding="utf-8")
        log = scenario_root / "gh.log"
        env = safe_env.copy()
        env.update({
            "PATH": str(temp_dir) + os.pathsep + safe_env["PATH"],
            "RUNNER_TEMP": str(scenario_root),
            "GH_REPO": "julubileu/jayflow-releases",
            "GH_TOKEN": "fake-token",
            "VERSION": version,
            "SOURCE_REF": "v" + version,
            "SOURCE_SHA": "0123456789abcdef0123456789abcdef01234567",
            "PUBLIC_KEY": vector_public,
            "FAKE_GH_LOG": str(log),
            "FAKE_GH_STATE": str(state),
            "FAKE_GH_REMOTE": str(remote),
            "FAKE_GH_FAIL": failure,
        })
        runner_tool = scenario_root / "jayflow-release-tool"
        shutil.copyfile(tool, runner_tool)
        runner_tool.chmod(0o755)
        result = checked(["bash", "-c", publish_script], cwd=scenario_root, env=env)
        if (result.returncode == 0) != should_pass:
            expectation = "pass" if should_pass else "fail"
            details = result.stderr.strip() or result.stdout.strip()
            raise SystemExit(f"publication {scenario} should {expectation}: {details}")
        calls = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        final_state = json.loads(state.read_text(encoding="utf-8"))
        return [call for call in calls if call[:1] == ["release"]], final_state, remote

    scenario_results = {
        "absent": publication_scenario("absent", True),
        "draft-empty": publication_scenario("draft-empty", True),
        "draft-partial-common": publication_scenario("draft-partial-common", True),
        "draft-with-windows-latest": publication_scenario("draft-with-windows-latest", True),
        "draft-complete": publication_scenario("draft-complete", True),
        "draft-extra": publication_scenario("draft-extra", False),
        "published-identical": publication_scenario("published-identical", True),
        "published-missing-linux": publication_scenario("published-missing-linux", False),
        "published-extra": publication_scenario("published-extra", False),
        "published-different-linux": publication_scenario("published-different-linux", False),
    }
    scenario_calls = {scenario: result[0] for scenario, result in scenario_results.items()}
    scenario_states = {scenario: result[1] for scenario, result in scenario_results.items()}
    scenario_remotes = {scenario: result[2] for scenario, result in scenario_results.items()}
    expected_orders = {
        "absent": ["view", "create", "upload", "upload", "upload", "view", "download", "edit"],
        "draft-empty": ["view", "upload", "upload", "upload", "view", "download", "edit"],
        "draft-partial-common": ["view", "upload", "upload", "upload", "view", "download", "edit"],
        "draft-with-windows-latest": ["view", "upload", "upload", "upload", "view", "download", "edit"],
        "draft-complete": ["view", "upload", "upload", "upload", "view", "download", "edit"],
        "draft-extra": ["view"],
        "published-identical": ["view", "download", "edit"],
        "published-missing-linux": ["view"],
        "published-extra": ["view"],
        "published-different-linux": ["view", "download"],
    }
    for scenario, calls in scenario_calls.items():
        order = [call[1] for call in calls]
        if order != expected_orders[scenario]:
            raise SystemExit(f"publication {scenario} command order is {order}, want {expected_orders[scenario]}")
    for scenario in ("absent", "draft-empty", "draft-partial-common", "draft-with-windows-latest", "draft-complete"):
        uploads = [call for call in scenario_calls[scenario] if call[1] == "upload"]
        common_names = [pathlib.Path(value).name for value in uploads[0][3:uploads[0].index("--repo")]]
        if len(common_names) != 8 or "latest.json" in common_names or "linux-latest.json" in common_names:
            raise SystemExit(f"publication {scenario} does not upload exactly eight common assets first")
        if [pathlib.Path(value).name for value in uploads[1][3:4]] != ["latest.json"]:
            raise SystemExit(f"publication {scenario} does not upload latest.json alone after common assets")
        if [pathlib.Path(value).name for value in uploads[2][3:4]] != ["linux-latest.json"]:
            raise SystemExit(f"publication {scenario} does not upload linux-latest.json alone and last")
        for index, upload_call in enumerate(uploads):
            if "--clobber" not in upload_call:
                raise SystemExit(f"publication {scenario} upload {index} cannot reconcile a partial draft without --clobber")
    reconciled_drafts = (
        "absent", "draft-empty", "draft-partial-common", "draft-with-windows-latest", "draft-complete",
    )
    create_calls = [call for call in scenario_calls["absent"] if call[1] == "create"]
    if len(create_calls) != 1 or "--draft" not in create_calls[0]:
        raise SystemExit("an absent release must be created as a draft")
    if "--draft=false" in create_calls[0] or "--latest" in create_calls[0]:
        raise SystemExit("release creation must never publish or mark latest")
    for scenario in reconciled_drafts + ("published-identical",):
        edit_calls = [call for call in scenario_calls[scenario] if call[1] == "edit"]
        if len(edit_calls) != 1:
            raise SystemExit(f"publication {scenario} must promote/reconcile exactly once")
        for flag in ("--draft=false", "--prerelease=false", "--latest"):
            if flag not in edit_calls[0]:
                raise SystemExit(f"publication {scenario} promotion is missing {flag}")
        if scenario_states[scenario]["draft"] is not False:
            raise SystemExit(f"publication {scenario} did not leave a promoted public release")
    for scenario in reconciled_drafts:
        remote_names = sorted(path.name for path in scenario_remotes[scenario].iterdir())
        if remote_names != sorted(expected_assets):
            raise SystemExit(f"publication {scenario} remote inventory is {remote_names}, want the ten assets")
    if scenario_states["draft-extra"]["draft"] is not True:
        raise SystemExit("an unexpected draft asset must leave a recoverable draft")
    if not (scenario_remotes["draft-extra"] / "unexpected.bin").exists():
        raise SystemExit("an unexpected draft asset must fail without deletion")
    if any(call[1] in {"upload", "create"} for call in scenario_calls["published-identical"]):
        raise SystemExit("published-identical rerun mutated immutable assets")
    for immutable_failure in ("published-missing-linux", "published-extra", "published-different-linux"):
        if any(call[1] in {"upload", "create", "edit"} for call in scenario_calls[immutable_failure]):
            raise SystemExit(f"{immutable_failure} mutated an immutable public release")

    failure_results = {
        "create": publication_scenario("fail-create", False, initial="absent", failure="create"),
        "upload-common": publication_scenario(
            "fail-upload-common", False, initial="absent", failure="upload-common"
        ),
        "upload-windows-latest": publication_scenario(
            "fail-upload-windows-latest", False, initial="absent", failure="upload-windows-latest"
        ),
        "upload-linux-latest": publication_scenario(
            "fail-upload-linux-latest", False, initial="absent", failure="upload-linux-latest"
        ),
        "final-view": publication_scenario("fail-final-view", False, initial="absent", failure="final-view"),
        "download": publication_scenario("fail-download", False, initial="absent", failure="download"),
        "remote-verify": publication_scenario("fail-remote-verify", False, initial="absent", failure="remote-verify"),
        "edit-final": publication_scenario(
            "fail-edit-final", False, initial="absent", failure="edit-final"
        ),
    }
    expected_failure_orders = {
        "create": ["view", "create"],
        "upload-common": ["view", "create", "upload"],
        "upload-windows-latest": ["view", "create", "upload", "upload"],
        "upload-linux-latest": ["view", "create", "upload", "upload", "upload"],
        "final-view": ["view", "create", "upload", "upload", "upload", "view"],
        "download": ["view", "create", "upload", "upload", "upload", "view", "download"],
        "remote-verify": ["view", "create", "upload", "upload", "upload", "view", "download"],
        "edit-final": ["view", "create", "upload", "upload", "upload", "view", "download", "edit"],
    }
    for failure, (calls, final_state, remote_dir) in failure_results.items():
        order = [call[1] for call in calls]
        if order != expected_failure_orders[failure]:
            raise SystemExit(f"publication failure {failure} order is {order}, want {expected_failure_orders[failure]}")
        if any(call[1] == "delete" for call in calls):
            raise SystemExit(f"publication failure {failure} attempted forbidden deletion")
        if failure != "create" and not final_state["draft"]:
            raise SystemExit(f"publication failure {failure} did not leave a recoverable draft")
    if "linux-latest.json" in failure_results["upload-linux-latest"][1]["assets"]:
        raise SystemExit("failed Linux manifest upload nevertheless made linux-latest.json visible")
    if (failure_results["upload-linux-latest"][2] / "linux-latest.json").exists():
        raise SystemExit("failed Linux manifest upload left linux-latest.json in the remote fixture")
    if failure_results["edit-final"][1]["draft"] is not True:
        raise SystemExit("latest became public before the final successful edit")

    premature_calls, _, _ = publication_scenario(
        "fail-premature-public", False, initial="absent", failure="premature-public"
    )
    if [call[1] for call in premature_calls] != ["view", "create", "upload", "upload", "upload", "view"]:
        raise SystemExit(
            "a release that turned public before verification must stop at the pre-promotion read: "
            f"{[call[1] for call in premature_calls]}"
        )
    if any(call[1] in {"download", "edit", "delete"} for call in premature_calls):
        raise SystemExit("a prematurely public release must not be verified, promoted, or deleted")
PY

gofmt_diff="$(gofmt -d "$ROOT/cmd/release-tool/main.go" "$ROOT/cmd/release-tool/main_test.go")"
[ -z "$gofmt_diff" ] || fail "release-tool Go files are not gofmt-clean"

(cd "$ROOT" && go test ./cmd/release-tool)
(cd "$ROOT" && go vet ./cmd/release-tool)
(cd "$ROOT" && git diff --check)

require_text "Releases/latest" "$ROOT/README.md"
require_text "JayFlow-setup.exe" "$ROOT/README.md"
require_text "release-manifest.json" "$ROOT/README.md"
require_text "release-manifest.sig" "$ROOT/README.md"
require_text "verify-bundle" "$ROOT/README.md"
require_text "X.Y.Z.0" "$ROOT/README.md"
require_text "Authenticode" "$ROOT/README.md"
require_text "aviso do Windows" "$ROOT/README.md"
require_text "LOCALAPPDATA" "$ROOT/README.md"
require_text "Ed25519" "$ROOT/SECURITY.md"
require_text "Authenticode" "$ROOT/SECURITY.md"
require_text "certificado" "$ROOT/SECURITY.md"
require_text "release-manifest.json" "$ROOT/SECURITY.md"
require_text "checksums.txt" "$ROOT/SECURITY.md"
reject_text "release delete" "$WORKFLOW"
reject_text "actions/checkout@v" "$WORKFLOW"
reject_text "actions/setup-go@v" "$WORKFLOW"
reject_text "actions/setup-node@v" "$WORKFLOW"
reject_text "actions/upload-artifact@v" "$WORKFLOW"
reject_text "actions/download-artifact@v" "$WORKFLOW"

printf 'release repository validation passed\n'
