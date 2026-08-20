package main

import (
	"bytes"
	"crypto/ed25519"
	"debug/elf"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
)

func TestSigningPayloadMatchesUpdaterContract(t *testing.T) {
	want := "jayflow-update-v1\n2.0.33-dev\nabcdef0123456789\n"
	if got := string(signingPayload(" v2.0.33-dev ", " ABCDEF0123456789 ")); got != want {
		t.Fatalf("signingPayload() = %q, want %q", got, want)
	}
}

func TestEd25519RFC8032VectorOne(t *testing.T) {
	seed := mustHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	wantPublic := mustHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	wantSignature := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
		"5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
	private := ed25519.NewKeyFromSeed(seed)
	if got := private.Public().(ed25519.PublicKey); !equalBytes(got, wantPublic) {
		t.Fatalf("public key = %x, want %x", got, wantPublic)
	}
	if got := hex.EncodeToString(signDetached(private, nil)); got != wantSignature {
		t.Fatalf("signature = %s, want %s", got, wantSignature)
	}
}

func TestSignAndVerifyBundleAuthenticatesEveryDistributedArtifact(t *testing.T) {
	dir := t.TempDir()
	version := "2.0.33-dev"
	writeUnsignedFixture(t, dir, version)
	private := vectorPrivateKey(t)
	url := "https://github.com/julubileu/jayflow-releases/releases/download/v2.0.33-dev/JayFlow-2.0.33-dev.exe"

	if err := signBundle(dir, version, url, private); err != nil {
		t.Fatalf("signBundle() error = %v", err)
	}
	public := private.Public().(ed25519.PublicKey)
	if err := verifyBundle(dir, version, url, public); err != nil {
		t.Fatalf("verifyBundle() error = %v", err)
	}

	for _, name := range unsignedAssetNames(version) {
		t.Run("tampered_"+name, func(t *testing.T) {
			copyDir := t.TempDir()
			copyFiles(t, dir, copyDir)
			path := filepath.Join(copyDir, name)
			handle, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := handle.WriteString("tamper"); err != nil {
				t.Fatal(err)
			}
			if err := handle.Close(); err != nil {
				t.Fatal(err)
			}
			if err := verifyBundle(copyDir, version, url, public); err == nil {
				t.Fatal("verifyBundle() accepted a tampered distributed artifact")
			}
		})
	}
}

func TestVerifyBundleRejectsMissingAndExtraFiles(t *testing.T) {
	version := "2.0.33-dev"
	private := vectorPrivateKey(t)
	url := "https://example.invalid/JayFlow-2.0.33-dev.exe"
	makeBundle := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		writeUnsignedFixture(t, dir, version)
		if err := signBundle(dir, version, url, private); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	t.Run("missing", func(t *testing.T) {
		dir := makeBundle(t)
		if err := os.Remove(filepath.Join(dir, "buildinfo.txt")); err != nil {
			t.Fatal(err)
		}
		if err := verifyBundle(dir, version, url, private.Public().(ed25519.PublicKey)); err == nil {
			t.Fatal("verifyBundle() accepted a missing asset")
		}
	})
	t.Run("extra", func(t *testing.T) {
		dir := makeBundle(t)
		if err := os.WriteFile(filepath.Join(dir, "unexpected.exe"), []byte("extra"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := verifyBundle(dir, version, url, private.Public().(ed25519.PublicKey)); err == nil {
			t.Fatal("verifyBundle() accepted an extra asset")
		}
	})
}

func TestReleaseToolRejectsSymlinkAndNonRegularInputs(t *testing.T) {
	version := "2.0.33-dev"

	t.Run("symlink asset", func(t *testing.T) {
		dir := t.TempDir()
		writeUnsignedFixture(t, dir, version)
		outside := filepath.Join(t.TempDir(), "outside.exe")
		if err := os.WriteFile(outside, []byte("outside"), 0o644); err != nil {
			t.Fatal(err)
		}
		asset := filepath.Join(dir, "JayFlow-"+version+".exe")
		if err := os.Remove(asset); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, asset); err != nil {
			t.Fatal(err)
		}
		if err := requireExactInventory(dir, unsignedAssetNames(version)); err == nil {
			t.Fatal("requireExactInventory() accepted a symlink asset")
		}
		if _, _, err := hashFile(asset); err == nil {
			t.Fatal("hashFile() followed a symlink asset")
		}
	})

	t.Run("fifo asset", func(t *testing.T) {
		dir := t.TempDir()
		writeUnsignedFixture(t, dir, version)
		asset := filepath.Join(dir, "JayFlow-"+version+".exe")
		if err := os.Remove(asset); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(asset, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := requireExactInventory(dir, unsignedAssetNames(version)); err == nil {
			t.Fatal("requireExactInventory() accepted a FIFO asset")
		}
	})

	t.Run("symlink directory", func(t *testing.T) {
		realDir := t.TempDir()
		writeUnsignedFixture(t, realDir, version)
		link := filepath.Join(t.TempDir(), "dist")
		if err := os.Symlink(realDir, link); err != nil {
			t.Fatal(err)
		}
		if err := requireExactInventory(link, unsignedAssetNames(version)); err == nil {
			t.Fatal("requireExactInventory() followed a symlink directory")
		}
	})
}

func TestReleaseToolNeverFollowsSymlinkOutputs(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, latestName)
	if err := os.Symlink(outside, output); err != nil {
		t.Fatal(err)
	}
	if err := writeNewRegularFile(output, []byte("overwritten"), 0o644); err == nil {
		t.Fatal("writeNewRegularFile() followed a symlink output")
	}
	body, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "unchanged" {
		t.Fatalf("outside target was modified: %q", body)
	}
}

func TestChecksumsCoverEveryAssetExceptTheChecksumFileItself(t *testing.T) {
	dir := t.TempDir()
	version := "2.0.33-dev"
	writeUnsignedFixture(t, dir, version)
	private := vectorPrivateKey(t)
	url := "https://example.invalid/JayFlow-2.0.33-dev.exe"
	if err := signBundle(dir, version, url, private); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(dir, checksumsName))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, name := range checksumCoveredNames(version) {
		if !strings.Contains(text, "  "+name+"\n") {
			t.Errorf("checksums.txt does not cover %s", name)
		}
	}
	if strings.Contains(text, "  "+checksumsName+"\n") {
		t.Fatal("checksums.txt contains an impossible self-hash")
	}
}

func TestPrivateKeyEnvironmentUsesGoSigntoolRawKeyFormat(t *testing.T) {
	private := vectorPrivateKey(t)
	t.Setenv(privateKeyEnv, base64.StdEncoding.EncodeToString(private))
	got, err := privateKeyFromEnv()
	if err != nil {
		t.Fatalf("privateKeyFromEnv() error = %v", err)
	}
	if !equalBytes(got, private) {
		t.Fatal("privateKeyFromEnv() changed the raw 64-byte Ed25519 key")
	}
}

func TestValidateVersionEnforcesWindowsBounds(t *testing.T) {
	for _, valid := range []string{"0.0.0", "2.0.33-dev", "65535.65535.65535"} {
		if _, err := validateVersion(valid); err != nil {
			t.Errorf("validateVersion(%q) error = %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"01.2.3", "1.02.3", "1.2.03", "65536.1.1", "1.65536.1", "1.1.65536",
		"1.2.3-rc1", "v1.2.3", "1.2.3+build",
	} {
		if _, err := validateVersion(invalid); err == nil {
			t.Errorf("validateVersion(%q) succeeded, want failure", invalid)
		}
	}
}

func TestFindFourPartVersionResource(t *testing.T) {
	resource := make([]byte, 80)
	copy(resource[12:], []byte{0xbd, 0x04, 0xef, 0xfe})
	putVersionWords(resource[20:], [4]uint16{2, 0, 33, 0})
	if err := verifyFourPartVersion(resource, [4]uint16{2, 0, 33, 0}); err != nil {
		t.Fatalf("verifyFourPartVersion(file version with empty product version) error = %v", err)
	}
	if err := verifyFourPartVersion(resource, [4]uint16{2, 0, 34, 0}); err == nil {
		t.Fatal("verifyFourPartVersion() accepted a different version")
	}
}

func TestVerifyNSISFirstHeaderRequiresCanonicalOverlay(t *testing.T) {
	const overlayOffset = 64
	valid := make([]byte, overlayOffset+28+96)
	binary.LittleEndian.PutUint32(valid[overlayOffset:], 0)
	binary.LittleEndian.PutUint32(valid[overlayOffset+4:], 0xdeadbeef)
	copy(valid[overlayOffset+8:], "NullsoftInst")
	binary.LittleEndian.PutUint32(valid[overlayOffset+20:], 32)
	binary.LittleEndian.PutUint32(valid[overlayOffset+24:], uint32(len(valid)-overlayOffset))

	if err := verifyNSISFirstHeader(valid, overlayOffset); err != nil {
		t.Fatalf("verifyNSISFirstHeader(valid) error = %v", err)
	}
	for name, mutate := range map[string]func([]byte){
		"signature": func(body []byte) { body[overlayOffset+4] ^= 1 },
		"brand":     func(body []byte) { body[overlayOffset+8] ^= 1 },
		"flags": func(body []byte) {
			binary.LittleEndian.PutUint32(body[overlayOffset:], 0x10)
		},
		"zero header": func(body []byte) {
			binary.LittleEndian.PutUint32(body[overlayOffset+20:], 0)
		},
		"negative header": func(body []byte) {
			binary.LittleEndian.PutUint32(body[overlayOffset+20:], 0xffffffff)
		},
		"short total": func(body []byte) {
			binary.LittleEndian.PutUint32(body[overlayOffset+24:], 27)
		},
		"wrong total": func(body []byte) {
			binary.LittleEndian.PutUint32(body[overlayOffset+24:], uint32(len(body)-overlayOffset-1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			body := append([]byte(nil), valid...)
			mutate(body)
			if err := verifyNSISFirstHeader(body, overlayOffset); err == nil {
				t.Fatal("verifyNSISFirstHeader() accepted a malformed NSIS overlay")
			}
		})
	}
	if err := verifyNSISFirstHeader(valid, overlayOffset-1); err == nil {
		t.Fatal("verifyNSISFirstHeader() accepted NullsoftInst at a non-overlay offset")
	}
	if err := verifyNSISFirstHeader(make([]byte, overlayOffset), overlayOffset); err == nil {
		t.Fatal("verifyNSISFirstHeader() accepted a portable PE without an NSIS overlay")
	}
}

func TestRequireNoAuthenticodeRejectsCertificateTable(t *testing.T) {
	header := &pe.OptionalHeader64{}
	file := &pe.File{OptionalHeader: header}
	if err := requireNoAuthenticode(file); err != nil {
		t.Fatalf("requireNoAuthenticode(unsigned) error = %v", err)
	}
	header.DataDirectory[4] = pe.DataDirectory{VirtualAddress: 1234, Size: 256}
	if err := requireNoAuthenticode(file); err == nil {
		t.Fatal("requireNoAuthenticode() accepted an Authenticode certificate table")
	}
}

func TestBuildinfoRecordsExactTagSHAAndWindowsInstallMetadata(t *testing.T) {
	sourceRef := "v2.0.33-dev"
	sourceSHA := "0123456789abcdef0123456789abcdef01234567"
	valid := "version=2.0.33-dev\n" +
		"source_ref=" + sourceRef + "\n" +
		"source_sha=" + sourceSHA + "\n" +
		"windows_file_version=2.0.33.0\n" +
		"install_scope=user\n" +
		"install_dir=%LOCALAPPDATA%\\Programs\\JayFlow\n"
	if err := validateBuildinfo([]byte(valid), "2.0.33-dev", sourceRef, sourceSHA); err != nil {
		t.Fatalf("validateBuildinfo(valid) error = %v", err)
	}
	for name, invalid := range map[string]string{
		"arbitrary ref": strings.Replace(valid, "source_ref=v2.0.33-dev", "source_ref=main", 1),
		"bad sha":       strings.Replace(valid, "0123456789abcdef0123456789abcdef01234567", "not-a-sha", 1),
		"machine scope": strings.Replace(valid, "install_scope=user", "install_scope=machine", 1),
		"program files": strings.Replace(valid, "%LOCALAPPDATA%", "%ProgramFiles%", 1),
		"three parts":   strings.Replace(valid, "windows_file_version=2.0.33.0", "windows_file_version=2.0.33", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateBuildinfo([]byte(invalid), "2.0.33-dev", sourceRef, sourceSHA); err == nil {
				t.Fatal("validateBuildinfo() accepted incorrect build metadata")
			}
		})
	}
	if err := validateBuildinfo([]byte(valid), "2.0.33-dev", sourceRef,
		"ffffffffffffffffffffffffffffffffffffffff"); err == nil {
		t.Fatal("validateBuildinfo() accepted a SHA different from the expected source")
	}
}

func TestPortableSourceIdentityRequiresExactPEMarkerAndChecksOptionalGoRevision(t *testing.T) {
	const sourceSHA = "0123456789abcdef0123456789abcdef01234567"
	const differentSHA = "ffffffffffffffffffffffffffffffffffffffff"
	matchingMarker := testPEString("source_sha=" + sourceSHA)
	differentMarker := testPEString("source_sha=" + differentSHA)
	matchingRevision := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: sourceSHA},
	}}
	differentRevision := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: differentSHA},
	}}

	tests := []struct {
		name    string
		body    []byte
		info    *debug.BuildInfo
		wantErr bool
	}{
		{name: "marker absent and vcs absent", body: []byte("PE fixture"), info: &debug.BuildInfo{}, wantErr: true},
		{name: "marker divergent and vcs absent", body: differentMarker, info: &debug.BuildInfo{}, wantErr: true},
		{name: "marker exact and vcs absent", body: matchingMarker, info: &debug.BuildInfo{}},
		{name: "marker exact and vcs present equal", body: matchingMarker, info: matchingRevision},
		{name: "marker exact and vcs present divergent", body: matchingMarker, info: differentRevision, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := requirePortableSourceIdentity(test.body, test.info, sourceSHA)
			if (err != nil) != test.wantErr {
				t.Fatalf("requirePortableSourceIdentity() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestPESourceMarkerIsStrictUTF16LEString(t *testing.T) {
	const sourceSHA = "0123456789abcdef0123456789abcdef01234567"
	valid := testPEString("source_sha=" + sourceSHA)
	if err := requirePESourceMarker(valid, sourceSHA); err != nil {
		t.Fatalf("requirePESourceMarker(valid) error = %v", err)
	}

	for name, body := range map[string][]byte{
		"ASCII marker":             []byte("\x00source_sha=" + sourceSHA + "\x00"),
		"uppercase SHA":            testPEString("source_sha=0123456789ABCDEF0123456789ABCDEF01234567"),
		"short SHA":                testPEString("source_sha=0123456789abcdef"),
		"extra hex digit":          testPEString("source_sha=" + sourceSHA + "a"),
		"missing leading boundary": append([]byte{1, 0}, valid[2:]...),
		"missing NUL terminator":   valid[:len(valid)-2],
		"matching plus divergent marker": append(append([]byte(nil), valid...),
			testPEString("source_sha=ffffffffffffffffffffffffffffffffffffffff")...),
	} {
		t.Run(name, func(t *testing.T) {
			if err := requirePESourceMarker(body, sourceSHA); err == nil {
				t.Fatal("requirePESourceMarker() accepted a non-exact PE string marker")
			}
		})
	}
}

func TestPortableContainsExactAuditedDaemonBytes(t *testing.T) {
	daemon := []byte("\x7fELF audited daemon bytes including zeros\x00\x01")
	portable := append([]byte("PE prefix"), daemon...)
	portable = append(portable, []byte("PE suffix")...)
	if err := requireEmbeddedBlob(portable, daemon); err != nil {
		t.Fatalf("requireEmbeddedBlob(exact) error = %v", err)
	}
	corrupted := append([]byte(nil), daemon...)
	corrupted[len(corrupted)/2] ^= 1
	if err := requireEmbeddedBlob(portable, corrupted); err == nil {
		t.Fatal("requireEmbeddedBlob() accepted a corrupted daemon")
	}
	if err := requireEmbeddedBlob([]byte("PE without daemon"), daemon); err == nil {
		t.Fatal("requireEmbeddedBlob() accepted a missing daemon")
	}
	if err := requireEmbeddedBlob(portable, nil); err == nil {
		t.Fatal("requireEmbeddedBlob() accepted an empty daemon")
	}
}

func TestAuditWindowsAdversarialRealBinaries(t *testing.T) {
	fixture := buildAuditableWindowsFixture(t)
	executionMarker := filepath.Join(t.TempDir(), "daemon-executed")
	t.Setenv("JAYFLOW_TEST_EXEC_MARKER", executionMarker)
	args := []string{
		"audit-windows",
		"-version", fixture.version,
		"-dir", fixture.dist,
		"-daemon", fixture.daemon,
		"-source-ref", fixture.sourceRef,
		"-source-sha", fixture.sourceSHA,
		"-public-key", fixture.publicKey,
	}
	if err := run(args); err != nil {
		t.Fatalf("audit-windows valid fixture error = %v", err)
	}
	if _, err := os.Lstat(executionMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("audit-windows executed the transported private-source daemon")
	}

	t.Run("daemon corrupted after audit", func(t *testing.T) {
		daemon := filepath.Join(t.TempDir(), "jayflowd")
		body, err := os.ReadFile(fixture.daemon)
		if err != nil {
			t.Fatal(err)
		}
		elfFile, err := elf.Open(fixture.daemon)
		if err != nil {
			t.Fatal(err)
		}
		note := elfFile.Section(".note.go.buildid")
		if note == nil || note.Size == 0 {
			_ = elfFile.Close()
			t.Fatal("test ELF has no Go build ID note")
		}
		offset := int(note.Offset + note.Size - 1)
		if err := elfFile.Close(); err != nil {
			t.Fatal(err)
		}
		body[offset] ^= 1
		if err := os.WriteFile(daemon, body, 0o755); err != nil {
			t.Fatal(err)
		}
		badArgs := replaceArgument(args, "-daemon", daemon)
		if err := run(badArgs); err == nil {
			t.Fatal("audit-windows accepted daemon bytes different from the embedded ELF")
		}
	})

	t.Run("daemon zeroed in portable", func(t *testing.T) {
		dist := cloneDirectory(t, fixture.dist)
		portablePath := filepath.Join(dist, "JayFlow-"+fixture.version+".exe")
		portable, err := os.ReadFile(portablePath)
		if err != nil {
			t.Fatal(err)
		}
		daemon, err := os.ReadFile(fixture.daemon)
		if err != nil {
			t.Fatal(err)
		}
		index := bytes.Index(portable, daemon)
		if index < 0 {
			t.Fatal("test fixture did not embed the daemon")
		}
		clear(portable[index : index+len(daemon)])
		if err := os.WriteFile(portablePath, portable, 0o644); err != nil {
			t.Fatal(err)
		}
		badArgs := replaceArgument(args, "-dir", dist)
		if err := run(badArgs); err == nil {
			t.Fatal("audit-windows accepted a portable with the embedded daemon zeroed")
		}
	})

	t.Run("daemon file absent", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing-jayflowd")
		badArgs := replaceArgument(args, "-daemon", missing)
		if err := run(badArgs); err == nil {
			t.Fatal("audit-windows accepted an absent audited daemon file")
		}
	})

	t.Run("portable renamed as setup", func(t *testing.T) {
		dist := cloneDirectory(t, fixture.dist)
		portable, err := os.ReadFile(filepath.Join(dist, "JayFlow-"+fixture.version+".exe"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"JayFlow-" + fixture.version + "-setup.exe", "JayFlow-setup.exe"} {
			if err := os.WriteFile(filepath.Join(dist, name), portable, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		badArgs := replaceArgument(args, "-dir", dist)
		if err := run(badArgs); err == nil {
			t.Fatal("audit-windows accepted a portable renamed as an NSIS setup")
		}
	})

	t.Run("source SHA divergence", func(t *testing.T) {
		badArgs := replaceArgument(args, "-source-sha", "ffffffffffffffffffffffffffffffffffffffff")
		if err := run(badArgs); err == nil {
			t.Fatal("audit-windows accepted a source SHA different from buildinfo and vcs.revision")
		}
	})

	t.Run("source marker absent", func(t *testing.T) {
		dist := cloneDirectory(t, fixture.dist)
		portablePath := filepath.Join(dist, "JayFlow-"+fixture.version+".exe")
		replacePortableMarker(t, portablePath, fixture.sourceSHA, "")
		badArgs := replaceArgument(args, "-dir", dist)
		if err := run(badArgs); err == nil {
			t.Fatal("audit-windows accepted a portable without the PE source marker")
		}
	})

	t.Run("source marker divergence", func(t *testing.T) {
		dist := cloneDirectory(t, fixture.dist)
		portablePath := filepath.Join(dist, "JayFlow-"+fixture.version+".exe")
		replacePortableMarker(t, portablePath, fixture.sourceSHA,
			"ffffffffffffffffffffffffffffffffffffffff")
		badArgs := replaceArgument(args, "-dir", dist)
		if err := run(badArgs); err == nil {
			t.Fatal("audit-windows accepted a divergent PE source marker")
		}
	})

	t.Run("symlink daemon", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "jayflowd")
		if err := os.Symlink(fixture.daemon, link); err != nil {
			t.Fatal(err)
		}
		badArgs := replaceArgument(args, "-daemon", link)
		if err := run(badArgs); err == nil {
			t.Fatal("audit-windows followed a daemon symlink")
		}
	})
}

type windowsAuditFixture struct {
	version   string
	dist      string
	daemon    string
	sourceRef string
	sourceSHA string
	publicKey string
}

func buildAuditableWindowsFixture(t *testing.T) windowsAuditFixture {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	sourceSHA := commandOutput(t, root, nil, "git", "rev-parse", "HEAD")
	fixtureRoot, err := os.MkdirTemp(root, ".release-audit-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(fixtureRoot); err != nil {
			t.Errorf("remove fixture: %v", err)
		}
	})
	if err := os.Mkdir(filepath.Join(fixtureRoot, "daemon"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(fixtureRoot, "portable"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(fixtureRoot, "go.mod"), "module fixture.invalid/audit\n\ngo 1.23.0\n")
	writeTestFile(t, filepath.Join(fixtureRoot, "daemon", "main.go"), `package main
import (
	"fmt"
	"os"
)
var Version = "unset"
func main() {
	if marker := os.Getenv("JAYFLOW_TEST_EXEC_MARKER"); marker != "" {
		if err := os.WriteFile(marker, []byte("executed"), 0600); err != nil {
			panic(err)
		}
	}
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(Version)
		return
	}
}
`)
	writeTestFile(t, filepath.Join(fixtureRoot, "portable", "main.go"), `package main
import (
	_ "embed"
	"fmt"
	"os"
)
//go:embed jayflowd
var daemon []byte
var Version = "unset"
var PublicKey = "unset"
func main() {
	if len(os.Args) > 99 {
		fmt.Println(Version, PublicKey, len(daemon))
	}
}
`)
	version := "2.0.33-dev"
	private := vectorPrivateKey(t)
	publicKey := base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	daemon := filepath.Join(fixtureRoot, "portable", "jayflowd")
	commonEnv := []string{
		"CGO_ENABLED=0",
		"SOURCE_DATE_EPOCH=1700000000",
	}
	runTestCommand(t, fixtureRoot, append(commonEnv, "GOOS=linux", "GOARCH=amd64"),
		"go", "build", "-buildvcs=true", "-trimpath", "-ldflags=-s -w -X main.Version="+version,
		"-o", daemon, "./daemon")
	basePortable := filepath.Join(fixtureRoot, "portable-base.exe")
	runTestCommand(t, fixtureRoot, append(commonEnv, "GOOS=windows", "GOARCH=amd64"),
		"go", "build", "-buildvcs=true", "-trimpath",
		"-ldflags=-s -w -X main.Version="+version+" -X main.PublicKey="+publicKey,
		"-o", basePortable, "./portable")

	baseBody, err := os.ReadFile(basePortable)
	if err != nil {
		t.Fatal(err)
	}
	marker := make([]byte, 24)
	copy(marker, []byte{0xbd, 0x04, 0xef, 0xfe})
	putVersionWords(marker[8:16], [4]uint16{2, 0, 33, 0})
	dist := filepath.Join(fixtureRoot, "dist")
	if err := os.Mkdir(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	portable := append(append([]byte(nil), baseBody...), testPEString("source_sha="+sourceSHA)...)
	portable = append(portable, marker...)
	if err := os.WriteFile(filepath.Join(dist, "JayFlow-"+version+".exe"), portable, 0o644); err != nil {
		t.Fatal(err)
	}

	peFile, err := pe.Open(basePortable)
	if err != nil {
		t.Fatal(err)
	}
	overlayOffset, err := peOverlayOffset(peFile, len(baseBody))
	if closeErr := peFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if overlayOffset < len(marker) {
		t.Fatal("test PE is too small for a version marker")
	}
	setup := append([]byte(nil), baseBody[:overlayOffset]...)
	copy(setup[overlayOffset-len(marker):], marker)
	firstHeader := make([]byte, 28+96)
	binary.LittleEndian.PutUint32(firstHeader[4:8], 0xdeadbeef)
	copy(firstHeader[8:20], "NullsoftInst")
	binary.LittleEndian.PutUint32(firstHeader[20:24], 32)
	binary.LittleEndian.PutUint32(firstHeader[24:28], uint32(len(firstHeader)))
	setup = append(setup, firstHeader...)
	for _, name := range []string{"JayFlow-" + version + "-setup.exe", "JayFlow-setup.exe"} {
		if err := os.WriteFile(filepath.Join(dist, name), setup, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sourceRef := "v" + version
	buildinfoText := "version=" + version + "\n" +
		"source_ref=" + sourceRef + "\n" +
		"source_sha=" + sourceSHA + "\n" +
		"windows_file_version=2.0.33.0\n" +
		"install_scope=user\n" +
		"install_dir=%LOCALAPPDATA%\\Programs\\JayFlow\n"
	writeTestFile(t, filepath.Join(dist, "buildinfo.txt"), buildinfoText)
	return windowsAuditFixture{
		version: version, dist: dist, daemon: daemon, sourceRef: sourceRef,
		sourceSHA: sourceSHA, publicKey: publicKey,
	}
}

func testPEString(value string) []byte {
	body := make([]byte, 2, 2+2*len(value)+2)
	for _, char := range []byte(value) {
		body = append(body, char, 0)
	}
	return append(body, 0, 0)
}

func replacePortableMarker(t *testing.T, path, oldSHA, newSHA string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	oldMarker := testPEString("source_sha=" + oldSHA)
	offset := bytes.Index(body, oldMarker)
	if offset < 0 {
		t.Fatal("test fixture has no source marker to replace")
	}
	replacement := make([]byte, len(oldMarker))
	if newSHA != "" {
		replacement = testPEString("source_sha=" + newSHA)
	}
	copy(body[offset:offset+len(oldMarker)], replacement)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func replaceArgument(args []string, flagName, value string) []string {
	result := append([]string(nil), args...)
	for index := 0; index+1 < len(result); index++ {
		if result[index] == flagName {
			result[index+1] = value
			return result
		}
	}
	panic("flag not found: " + flagName)
}

func cloneDirectory(t *testing.T, source string) string {
	t.Helper()
	destination := t.TempDir()
	copyFiles(t, source, destination)
	return destination
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commandOutput(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), env...)
	body, err := command.Output()
	if err != nil {
		t.Fatalf("%s %v failed: %v", name, args, err)
	}
	return strings.TrimSpace(string(body))
}

func runTestCommand(t *testing.T, dir string, env []string, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = dir
	command.Env = append(os.Environ(), env...)
	body, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, body)
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func vectorPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(mustHex(t,
		"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
}

func writeUnsignedFixture(t *testing.T, dir, version string) {
	t.Helper()
	contents := []string{"portable", "versioned installer", "versioned installer", "build info"}
	for index, name := range unsignedAssetNames(version) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents[index]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func copyFiles(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, entry.Name()), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
