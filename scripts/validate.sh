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
if not isinstance(jobs, dict) or set(jobs) != {"build", "sign_publish"}:
    raise SystemExit("workflow must have exactly separate build and sign_publish jobs")
build = jobs["build"]
sign = jobs["sign_publish"]
if build.get("permissions") != {"contents": "read"}:
    raise SystemExit("build permissions must remain read-only")
if sign.get("permissions") != {"contents": "write"}:
    raise SystemExit("sign_publish alone must receive contents: write")
if sign.get("needs") != "build":
    raise SystemExit("sign_publish must depend on build")
if build.get("runs-on") != "ubuntu-24.04" or sign.get("runs-on") != "ubuntu-24.04":
    raise SystemExit("both isolated jobs must use the audited runner image")


def serialized(value):
    return json.dumps(value, sort_keys=True)


build_text = serialized(build)
sign_text = serialized(sign)
if "JAYFLOW_RELEASE_PRIVATE_KEY" in build_text:
    raise SystemExit("release private key must never be present in the build job")
if "JAYFLOW_SOURCE_DEPLOY_KEY" in sign_text or "julubileu/jayflow-v2" in sign_text:
    raise SystemExit("sign_publish must never receive or check out private source")
if "go run" in sign_text:
    raise SystemExit("sign_publish must execute the precompiled public tool, never go run")
if set(re.findall(r"secrets\.([A-Za-z0-9_]+)", build_text)) != {"JAYFLOW_SOURCE_DEPLOY_KEY"}:
    raise SystemExit("build secret allowlist must contain only the read-only deploy key")
if set(re.findall(r"secrets\.([A-Za-z0-9_]+)", sign_text)) != {"JAYFLOW_RELEASE_PRIVATE_KEY"}:
    raise SystemExit("sign_publish secret allowlist must contain only the signing key")

build_steps = build.get("steps", [])
sign_steps = sign.get("steps", [])
if not isinstance(build_steps, list) or not isinstance(sign_steps, list):
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


require_order(names(build_steps), [
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
    "Upload the unsigned internal build artifact",
    "Upload the separately audited daemon artifact",
], "build")
require_order(names(sign_steps), [
    "Check out only the public release repository",
    "Test and compile the trusted public tool before secret injection",
    "Download the unsigned internal build artifact",
    "Download the separate audited daemon artifact",
    "Audit downloaded bytes before signing",
    "Derive and verify the release public key",
    "Sign final bytes and generate authenticated metadata",
    "Verify signed final bundle without the private key",
    "Create or reconcile the atomic public release",
], "sign_publish")

scripts = {}
actions = []
for job_name, steps in (("build", build_steps), ("sign_publish", sign_steps)):
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
    "actions/checkout": ("11bd71901bbe5b1630ceea73d27597364c9af683", "v4.2.2", 3),
    "actions/setup-go": ("d35c59abb061a4a6fb18e82ac0862c26744d6ab5", "v5.5.0", 2),
    "actions/setup-node": ("49933ea5288caeca8642d1e84afbd3f7d6820020", "v4.4.0", 1),
    "actions/upload-artifact": ("ea165f8d65b6e75b540449e92b4886f43607fa02", "v4.6.2", 2),
    "actions/download-artifact": ("d3f86a106a0bac45b974a628896c90dbdf5c8093", "v4.3.0", 2),
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


private_checkout = step_named(build_steps, "Check out the private source at the validated tag")
if private_checkout.get("with") != {
    "repository": "julubileu/jayflow-v2",
    "ref": "${{ steps.inputs.outputs.ref }}",
    "ssh-key": "${{ secrets.JAYFLOW_SOURCE_DEPLOY_KEY }}",
    "path": "source",
    "persist-credentials": "false",
}:
    raise SystemExit("private checkout is not exact-tag/read-only-key scoped")
public_sign_checkout = step_named(sign_steps, "Check out only the public release repository")
if "repository" in public_sign_checkout.get("with", {}):
    raise SystemExit("sign_publish checkout must only check out this public repository")
public_auditor_build = step_named(build_steps, "Build the trusted public auditor")
if public_auditor_build.get("working-directory") != "release":
    raise SystemExit("build must compile the nested public Go module from working-directory release")

upload = step_named(build_steps, "Upload the unsigned internal build artifact")
download = step_named(sign_steps, "Download the unsigned internal build artifact")
if upload.get("with", {}).get("name") != "unsigned-release-assets":
    raise SystemExit("build artifact has wrong name")
if upload.get("with", {}).get("if-no-files-found") != "error":
    raise SystemExit("artifact upload must fail when outputs are absent")
if download.get("with", {}).get("name") != "unsigned-release-assets":
    raise SystemExit("sign_publish does not download the exact build artifact")
daemon_upload = step_named(build_steps, "Upload the separately audited daemon artifact")
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
stamp_prefix, marker, build_suffix = stamp_script.partition("\nbuild_windows_app()")
if not marker:
    raise SystemExit("Windows build step does not define the reproducible app build function")
with tempfile.TemporaryDirectory() as temp_dir:
    config = pathlib.Path(temp_dir, "wails.json")
    config.write_text(
        '{"name":"jayflow","info":{"productName":"JayFlow","productVersion":"2.0.0-dev"}}\n',
        encoding="utf-8",
    )
    env = safe_env.copy()
    env.update({"VERSION": "2.0.33-dev", "PUBLIC_KEY": "test-public-key"})
    result = checked(["bash", "-c", stamp_prefix], cwd=temp_dir, env=env)
    require_success(result, "Wails metadata stamping")
    stamped = json.loads(config.read_text(encoding="utf-8"))
    if stamped["info"]["productVersion"] != "2.0.33":
        raise SystemExit("Wails productVersion must be numeric X.Y.Z")
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
    first_build < discover_output < select_output < date_save < first_makensis < preserve_first < restore < second_stamp
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
        '{"name":"jayflow","info":{"productName":"JayFlow","productVersion":"2.0.0-dev"}}\n',
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
):
    if required not in stage_script:
        raise SystemExit(f"output staging/audit is missing {required}")

downloaded_audit = scripts["Audit downloaded bytes before signing"]
for required in (
    '-daemon internal-daemon/jayflowd',
    '-source-ref "$SOURCE_REF"',
    '-source-sha "$SOURCE_SHA"',
):
    if required not in downloaded_audit:
        raise SystemExit(f"pre-secret downloaded audit is missing {required}")
downloaded_audit_env = step_named(sign_steps, "Audit downloaded bytes before signing").get("env", {})
if downloaded_audit_env.get("SOURCE_REF") != "${{ needs.build.outputs.ref }}":
    raise SystemExit("sign_publish audit source ref is not tied to build output")
if downloaded_audit_env.get("SOURCE_SHA") != "${{ needs.build.outputs.source_sha }}":
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
first_upload = publish_script.index('gh release upload "$TAG" "${NON_LATEST_ASSETS[@]}"')
latest_upload = publish_script.index('gh release upload "$TAG" dist/latest.json')
final_edit = publish_script.rindex('gh release edit "$TAG"')
if not first_upload < latest_upload < final_edit:
    raise SystemExit("atomic upload/latest/public order is wrong")

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
    }.items():
        (compatibility / name).write_bytes(body)
    portable_url = (
        "https://github.com/julubileu/jayflow-releases/releases/download/"
        f"v{version}/JayFlow-{version}.exe"
    )
    result = checked([
        str(tool), "sign-bundle", "-version", version, "-dir", str(compatibility),
        "-portable-url", portable_url,
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

def fail_if(point):
    if failure == point:
        print("injected gh failure: " + point, file=sys.stderr)
        raise SystemExit(42)

if args[:2] == ["release", "view"]:
    fail_if("view")
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
    fail_if("upload-latest" if names == ["latest.json"] else "upload-common")
    for value in args[3:repo_index]:
        name = pathlib.Path(value).name
        if name not in state["assets"]:
            state["assets"].append(name)
    state_path.write_text(json.dumps(state), encoding="utf-8")
elif args[:2] == ["release", "download"]:
    fail_if("download")
    destination = pathlib.Path(args[args.index("--dir") + 1])
    destination.mkdir(parents=True, exist_ok=True)
    for source in pathlib.Path(os.environ["FAKE_GH_REMOTE"]).iterdir():
        shutil.copyfile(source, destination / source.name)
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
    ]

    def publication_scenario(scenario, should_pass, *, initial=None, failure=""):
        scenario_root = temp_dir / scenario
        scenario_root.mkdir()
        dist = scenario_root / "dist"
        shutil.copytree(compatibility, dist)
        remote = scenario_root / "remote"
        remote.mkdir()
        initial = initial or scenario
        exists = initial != "new"
        draft = initial.startswith("draft")
        assets = []
        if initial == "draft-extra":
            assets = [expected_assets[0], "unexpected.bin"]
        elif initial == "published-missing":
            assets = expected_assets[:-1]
        elif initial == "published-extra":
            assets = expected_assets + ["unexpected.bin"]
        elif initial.startswith("published"):
            assets = expected_assets.copy()
        if initial.startswith("published"):
            for source in compatibility.iterdir():
                shutil.copyfile(source, remote / source.name)
        if initial == "published-tampered":
            with (remote / f"JayFlow-{version}.exe").open("ab") as handle:
                handle.write(b"tampered")
        state = scenario_root / "state.json"
        state.write_text(json.dumps({"exists": exists, "draft": draft, "assets": assets}), encoding="utf-8")
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
        return [call for call in calls if call[:1] == ["release"]], final_state

    scenario_calls = {
        "new": publication_scenario("new", True)[0],
        "draft": publication_scenario("draft", True)[0],
        "published-identical": publication_scenario("published-identical", True)[0],
        "published-tampered": publication_scenario("published-tampered", False)[0],
        "published-missing": publication_scenario("published-missing", False)[0],
        "published-extra": publication_scenario("published-extra", False)[0],
        "draft-extra": publication_scenario("draft-extra", False)[0],
    }
    expected_orders = {
        "new": ["view", "create", "upload", "upload", "view", "edit"],
        "draft": ["view", "upload", "upload", "view", "edit"],
        "published-identical": ["view", "download", "edit"],
        "published-tampered": ["view", "download"],
        "published-missing": ["view"],
        "published-extra": ["view"],
        "draft-extra": ["view"],
    }
    for scenario, calls in scenario_calls.items():
        order = [call[1] for call in calls]
        if order != expected_orders[scenario]:
            raise SystemExit(f"publication {scenario} command order is {order}, want {expected_orders[scenario]}")
    for scenario in ("new", "draft"):
        uploads = [call for call in scenario_calls[scenario] if call[1] == "upload"]
        if any(pathlib.Path(value).name == "latest.json" for value in uploads[0]):
            raise SystemExit(f"publication {scenario} uploads latest.json before metadata")
        if [pathlib.Path(value).name for value in uploads[1][3:4]] != ["latest.json"]:
            raise SystemExit(f"publication {scenario} does not upload latest.json alone and last")
    if any(call[1] in {"upload", "create"} for call in scenario_calls["published-identical"]):
        raise SystemExit("published-identical rerun mutated immutable assets")

    failure_results = {
        "view": publication_scenario("fail-view", False, initial="draft", failure="view"),
        "create": publication_scenario("fail-create", False, initial="new", failure="create"),
        "upload-common": publication_scenario(
            "fail-upload-common", False, initial="new", failure="upload-common"
        ),
        "upload-latest": publication_scenario(
            "fail-upload-latest", False, initial="new", failure="upload-latest"
        ),
        "download": publication_scenario(
            "fail-download", False, initial="published-identical", failure="download"
        ),
        "edit-final": publication_scenario(
            "fail-edit-final", False, initial="new", failure="edit-final"
        ),
    }
    expected_failure_orders = {
        "view": ["view"],
        "create": ["view", "create"],
        "upload-common": ["view", "create", "upload"],
        "upload-latest": ["view", "create", "upload", "upload"],
        "download": ["view", "download"],
        "edit-final": ["view", "create", "upload", "upload", "view", "edit"],
    }
    for failure, (calls, final_state) in failure_results.items():
        order = [call[1] for call in calls]
        if order != expected_failure_orders[failure]:
            raise SystemExit(f"publication failure {failure} order is {order}, want {expected_failure_orders[failure]}")
        if any(call[1] == "delete" for call in calls):
            raise SystemExit(f"publication failure {failure} attempted forbidden deletion")
        if failure in {"upload-common", "upload-latest", "edit-final"} and not final_state["draft"]:
            raise SystemExit(f"publication failure {failure} did not leave a recoverable draft")
    if "latest.json" in failure_results["upload-latest"][1]["assets"]:
        raise SystemExit("failed latest upload nevertheless made latest.json visible")
    if failure_results["edit-final"][1]["draft"] is not True:
        raise SystemExit("latest became public before the final successful edit")
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
