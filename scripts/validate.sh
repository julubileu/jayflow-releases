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
import json
import os
import pathlib
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
], "build_windows")
require_order(names(linux_steps), [
    "Validate release inputs",
    "Check out the private source at the validated tag",
    "Record and verify source identity",
    "Derive the reproducible source epoch",
    "Build the trusted public auditor",
    "Run focused Linux release gates",
    "Build and audit reproducible Linux gateway",
    "Upload the unsigned Linux gateway",
], "build_linux")
require_order(names(accept_steps), [
    "Check out the private source from the Linux build",
    "Verify accepted source identity",
    "Download the transported Linux gateway",
    "Build the acceptance daemon",
    "Audit transported Linux bytes",
    "Expose the runner browser as Chromium",
    "Install acceptance frontend dependencies",
    "Run real-systemd and Playwright acceptance",
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

acceptance_step = step_named(accept_steps, "Run real-systemd and Playwright acceptance")
if acceptance_step.get("env") != {
    "VERSION": "${{ needs.build_linux.outputs.version }}",
    "SOURCE_SHA": "${{ needs.build_linux.outputs.source_sha }}",
}:
    raise SystemExit("acceptance harness identity is not bound to build_linux")
acceptance_script = acceptance_step["run"]
exact_acceptance = '''sudo --preserve-env=JAYFLOW_CHROMIUM \\
  source/tests/mobile-release-systemd.sh \\
  --gateway "$PWD/candidate/jayflow-web-${VERSION}-linux-amd64" \\
  --daemon "$RUNNER_TEMP/jayflowd-acceptance" \\
  --version "$VERSION" \\
  --source-sha "$SOURCE_SHA" \\
  --playwright "$PWD/source/cmd/jayflow/frontend/scripts/mobile-release.playwright.mjs"'''
if exact_acceptance not in acceptance_script:
    raise SystemExit("accept_linux does not invoke the exact transported-byte systemd harness")
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
    harness = accept_temp / "source" / "tests" / "mobile-release-systemd.sh"
    harness.write_text(r'''#!/usr/bin/env bash
set -euo pipefail
printf 'harness %s\n' "$*" >> "$FAKE_ACCEPT_TOOL_LOG"
systemctl --user start jayflow-web.service
loginctl enable-linger fixture
runuser -u fixture -- true
useradd fixture
userdel fixture
"$JAYFLOW_CHROMIUM" --version
case "${FAKE_ACCEPT_FAILURE:-}" in
  "") ;;
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
''', encoding="utf-8")
    harness.chmod(0o755)
    fake_sudo = fake_bin / "sudo"
    fake_sudo.write_text(r'''#!/usr/bin/env bash
printf 'sudo %s\n' "$*" >> "$FAKE_ACCEPT_TOOL_LOG"
[ "${1:-}" = --preserve-env=JAYFLOW_CHROMIUM ] || exit 64
shift
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
    result = checked(["bash", "-c", acceptance_script], cwd=accept_temp, env=accept_env)
    require_success(result, "behavioral Linux systemd/Playwright acceptance")
    observed_tools = accept_log.read_text(encoding="utf-8")
    for required in ("sudo ", "harness ", "systemctl ", "loginctl ", "runuser ", "useradd ", "userdel ", "chromium "):
        if required not in observed_tools:
            raise SystemExit(f"acceptance simulator did not exercise stub {required.strip()}")
    for failure in (
        "service start", "health",
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
        result = checked(["bash", "-c", acceptance_script], cwd=accept_temp, env=failing_env)
        if result.returncode == 0:
            raise SystemExit(f"accept_linux accepted injected failure {failure}")

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
