// Command release-tool is the trusted, public JayFlow release signer, verifier,
// and binary auditor. It deliberately uses only the Go standard library.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"debug/buildinfo"
	"debug/elf"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
)

const (
	privateKeyEnv        = "JAYFLOW_RELEASE_PRIVATE_KEY"
	updateSigningDomain  = "jayflow-update-v1"
	releaseSigningDomain = "jayflow-release-manifest-v1"
	releaseSchema        = "jayflow-release-v1"
	latestName           = "latest.json"
	releaseManifestName  = "release-manifest.json"
	releaseSignatureName = "release-manifest.sig"
	checksumsName        = "checksums.txt"
)

var strictVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-dev)?$`)

type latestManifest struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Sig     string `json:"sig"`
}

type releaseAsset struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type releaseManifest struct {
	Schema  string         `json:"schema"`
	Version string         `json:"version"`
	Assets  []releaseAsset `json:"assets"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "release-tool:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("command required: pubkey, sign-bundle, verify-bundle, audit-daemon, or audit-windows")
	}
	switch args[0] {
	case "pubkey":
		if len(args) != 1 {
			return errors.New("pubkey takes no arguments")
		}
		private, err := privateKeyFromEnv()
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)))
		return nil
	case "sign-bundle":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		version := flags.String("version", "", "release version")
		dir := flags.String("dir", "", "artifact directory")
		url := flags.String("portable-url", "", "portable artifact URL")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return errors.New("usage: sign-bundle -version X.Y.Z[-dev] -dir DIR -portable-url HTTPS_URL")
		}
		private, err := privateKeyFromEnv()
		if err != nil {
			return err
		}
		return signBundle(*dir, *version, *url, private)
	case "verify-bundle":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		version := flags.String("version", "", "release version")
		dir := flags.String("dir", "", "artifact directory")
		url := flags.String("portable-url", "", "portable artifact URL")
		publicText := flags.String("public-key", "", "base64 Ed25519 public key")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return errors.New("usage: verify-bundle -version X.Y.Z[-dev] -dir DIR -portable-url HTTPS_URL -public-key BASE64")
		}
		public, err := decodePublicKey(*publicText)
		if err != nil {
			return err
		}
		return verifyBundle(*dir, *version, *url, public)
	case "audit-daemon":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		version := flags.String("version", "", "release version")
		path := flags.String("path", "", "jayflowd path")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return errors.New("usage: audit-daemon -version X.Y.Z[-dev] -path FILE")
		}
		return auditDaemon(*path, *version)
	case "audit-windows":
		flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		version := flags.String("version", "", "release version")
		dir := flags.String("dir", "", "artifact directory")
		daemon := flags.String("daemon", "", "audited embedded Linux daemon")
		sourceRef := flags.String("source-ref", "", "exact source tag")
		sourceSHA := flags.String("source-sha", "", "exact source commit")
		publicText := flags.String("public-key", "", "base64 Ed25519 public key")
		if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
			return errors.New("usage: audit-windows -version X.Y.Z[-dev] -dir DIR -daemon FILE -source-ref TAG -source-sha SHA -public-key BASE64")
		}
		if _, err := decodePublicKey(*publicText); err != nil {
			return err
		}
		return auditWindows(*dir, *daemon, *version, *sourceRef, *sourceSHA, *publicText)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func signBundle(dir, version, portableURL string, private ed25519.PrivateKey) error {
	if len(private) != ed25519.PrivateKeySize {
		return fmt.Errorf("private key is %d bytes, want %d", len(private), ed25519.PrivateKeySize)
	}
	if _, err := validateVersion(version); err != nil {
		return err
	}
	if err := validatePortableURL(portableURL, version); err != nil {
		return err
	}
	if err := requireExactInventory(dir, unsignedAssetNames(version)); err != nil {
		return fmt.Errorf("unsigned bundle: %w", err)
	}
	if err := requireIdenticalInstallers(dir, version); err != nil {
		return err
	}

	portable := filepath.Join(dir, "JayFlow-"+version+".exe")
	portableDigest, _, err := hashFile(portable)
	if err != nil {
		return err
	}
	latest := latestManifest{
		Version: version,
		URL:     portableURL,
		SHA256:  portableDigest,
	}
	latest.Sig = base64.StdEncoding.EncodeToString(signDetached(private,
		signingPayload(latest.Version, latest.SHA256)))
	if err := writeJSON(filepath.Join(dir, latestName), latest); err != nil {
		return err
	}

	release := releaseManifest{Schema: releaseSchema, Version: version}
	for _, name := range unsignedAssetNames(version) {
		digest, size, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		release.Assets = append(release.Assets, releaseAsset{Name: name, SHA256: digest, Size: size})
	}
	releaseBody, err := marshalJSON(release)
	if err != nil {
		return err
	}
	if err := writeNewRegularFile(filepath.Join(dir, releaseManifestName), releaseBody, 0o644); err != nil {
		return err
	}
	signature := base64.StdEncoding.EncodeToString(signDetached(private, releaseSigningPayload(releaseBody))) + "\n"
	if err := writeNewRegularFile(filepath.Join(dir, releaseSignatureName), []byte(signature), 0o644); err != nil {
		return err
	}
	checksums, err := generateChecksums(dir, version)
	if err != nil {
		return err
	}
	if err := writeNewRegularFile(filepath.Join(dir, checksumsName), checksums, 0o644); err != nil {
		return err
	}
	public := private.Public().(ed25519.PublicKey)
	if err := verifyBundle(dir, version, portableURL, public); err != nil {
		return fmt.Errorf("self-check: %w", err)
	}
	return nil
}

func verifyBundle(dir, version, portableURL string, public ed25519.PublicKey) error {
	if _, err := validateVersion(version); err != nil {
		return err
	}
	if err := validatePortableURL(portableURL, version); err != nil {
		return err
	}
	if len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("public key is %d bytes, want %d", len(public), ed25519.PublicKeySize)
	}
	if err := requireExactInventory(dir, signedAssetNames(version)); err != nil {
		return err
	}
	if err := requireIdenticalInstallers(dir, version); err != nil {
		return err
	}

	releaseBody, err := readRegularFile(filepath.Join(dir, releaseManifestName))
	if err != nil {
		return err
	}
	var release releaseManifest
	if err := decodeStrictJSON(releaseBody, &release); err != nil {
		return fmt.Errorf("%s: %w", releaseManifestName, err)
	}
	if release.Schema != releaseSchema || release.Version != version {
		return fmt.Errorf("%s has wrong schema or version", releaseManifestName)
	}
	expectedNames := unsignedAssetNames(version)
	if len(release.Assets) != len(expectedNames) {
		return fmt.Errorf("%s has %d assets, want %d", releaseManifestName, len(release.Assets), len(expectedNames))
	}
	for index, expectedName := range expectedNames {
		asset := release.Assets[index]
		if asset.Name != expectedName {
			return fmt.Errorf("%s asset %d is %q, want %q", releaseManifestName, index, asset.Name, expectedName)
		}
		digest, size, err := hashFile(filepath.Join(dir, asset.Name))
		if err != nil {
			return err
		}
		if !validDigest(asset.SHA256) || subtle.ConstantTimeCompare([]byte(digest), []byte(asset.SHA256)) != 1 || size != asset.Size {
			return fmt.Errorf("%s hash or size mismatch", asset.Name)
		}
	}
	signatureText, err := readRegularFile(filepath.Join(dir, releaseSignatureName))
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureText)))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%s is not a base64 Ed25519 signature", releaseSignatureName)
	}
	if !ed25519.Verify(public, releaseSigningPayload(releaseBody), signature) {
		return fmt.Errorf("%s signature is invalid", releaseManifestName)
	}

	latestBody, err := readRegularFile(filepath.Join(dir, latestName))
	if err != nil {
		return err
	}
	var latest latestManifest
	if err := decodeStrictJSON(latestBody, &latest); err != nil {
		return fmt.Errorf("%s: %w", latestName, err)
	}
	if latest.Version != version || latest.URL != portableURL || !validDigest(latest.SHA256) {
		return fmt.Errorf("%s has invalid version, URL, or digest", latestName)
	}
	latestSignature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(latest.Sig))
	if err != nil || len(latestSignature) != ed25519.SignatureSize {
		return fmt.Errorf("%s has invalid signature encoding", latestName)
	}
	if !ed25519.Verify(public, signingPayload(latest.Version, latest.SHA256), latestSignature) {
		return fmt.Errorf("%s signature is invalid", latestName)
	}
	portableDigest, _, err := hashFile(filepath.Join(dir, "JayFlow-"+version+".exe"))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(portableDigest), []byte(latest.SHA256)) != 1 {
		return fmt.Errorf("%s does not match portable bytes", latestName)
	}

	wantChecksums, err := generateChecksums(dir, version)
	if err != nil {
		return err
	}
	gotChecksums, err := readRegularFile(filepath.Join(dir, checksumsName))
	if err != nil {
		return err
	}
	if !bytes.Equal(gotChecksums, wantChecksums) {
		return fmt.Errorf("%s does not match final asset bytes", checksumsName)
	}
	return nil
}

func auditDaemon(path, version string) error {
	body, err := inspectDaemon(path, version)
	if err != nil {
		return err
	}
	auditDir, err := os.MkdirTemp("", "jayflow-daemon-audit-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(auditDir)
	auditPath := filepath.Join(auditDir, "jayflowd")
	if err := writeNewRegularFile(auditPath, body, 0o755); err != nil {
		return err
	}
	command := exec.Command(auditPath, "--version")
	stdout, err := command.Output()
	if err != nil {
		return fmt.Errorf("daemon --version failed: %w", err)
	}
	if string(stdout) != version+"\n" {
		return fmt.Errorf("daemon --version = %q, want %q", stdout, version+"\n")
	}
	return nil
}

func inspectDaemon(path, version string) ([]byte, error) {
	if _, err := validateVersion(version); err != nil {
		return nil, err
	}
	body, err := readRegularFile(path)
	if err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	file, err := elf.NewFile(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("daemon is not ELF: %w", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Machine != elf.EM_X86_64 {
		return nil, fmt.Errorf("daemon is %s/%s, want ELF64/amd64", file.Class, file.Machine)
	}
	info, err := buildinfo.Read(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("daemon has no Go build info: %w", err)
	}
	if err := requireGoTarget(info, "linux", "amd64"); err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	if !bytes.Contains(body, []byte(version)) {
		return nil, errors.New("daemon does not contain the stamped version")
	}
	return body, nil
}

func auditWindows(dir, daemonPath, version, sourceRef, sourceSHA, publicKey string) error {
	parts, err := validateVersion(version)
	if err != nil {
		return err
	}
	if err := validateSourceIdentity(version, sourceRef, sourceSHA); err != nil {
		return err
	}
	daemonBody, err := inspectDaemon(daemonPath, version)
	if err != nil {
		return fmt.Errorf("embedded daemon: %w", err)
	}
	if err := requireExactInventory(dir, unsignedAssetNames(version)); err != nil {
		return err
	}
	if err := requireIdenticalInstallers(dir, version); err != nil {
		return err
	}
	buildinfoBody, err := readRegularFile(filepath.Join(dir, "buildinfo.txt"))
	if err != nil {
		return err
	}
	if err := validateBuildinfo(buildinfoBody, version, sourceRef, sourceSHA); err != nil {
		return err
	}
	windowsVersion := [4]uint16{parts[0], parts[1], parts[2], 0}
	portablePath := filepath.Join(dir, "JayFlow-"+version+".exe")
	if err := auditPE(portablePath, pe.IMAGE_FILE_MACHINE_AMD64, windowsVersion); err != nil {
		return fmt.Errorf("portable: %w", err)
	}
	body, err := readRegularFile(portablePath)
	if err != nil {
		return err
	}
	info, err := buildinfo.Read(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("portable has no Go build info: %w", err)
	}
	if err := requireGoTarget(info, "windows", "amd64"); err != nil {
		return fmt.Errorf("portable: %w", err)
	}
	if err := requireVCSRevision(info, sourceSHA); err != nil {
		return fmt.Errorf("portable: %w", err)
	}
	if !bytes.Contains(body, []byte(version)) {
		return errors.New("portable does not contain the stamped AppVersion/DaemonVersion value")
	}
	if !bytes.Contains(body, []byte(publicKey)) {
		return errors.New("portable does not contain the configured Ed25519 public key")
	}
	if err := requireEmbeddedBlob(body, daemonBody); err != nil {
		return err
	}
	installerPath := filepath.Join(dir, "JayFlow-"+version+"-setup.exe")
	if err := auditPE(installerPath, 0, windowsVersion); err != nil {
		return fmt.Errorf("installer: %w", err)
	}
	if err := auditNSIS(installerPath); err != nil {
		return fmt.Errorf("installer: %w", err)
	}
	return nil
}

func validateBuildinfo(body []byte, version, sourceRef, sourceSHA string) error {
	parts, err := validateVersion(version)
	if err != nil {
		return err
	}
	if err := validateSourceIdentity(version, sourceRef, sourceSHA); err != nil {
		return err
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		return errors.New("buildinfo.txt must end with one newline")
	}
	lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
	if len(lines) != 6 {
		return fmt.Errorf("buildinfo.txt has %d lines, want 6", len(lines))
	}
	expected := []string{
		"version=" + version,
		"source_ref=" + sourceRef,
		"source_sha=" + sourceSHA,
		fmt.Sprintf("windows_file_version=%d.%d.%d.0", parts[0], parts[1], parts[2]),
		"install_scope=user",
		`install_dir=%LOCALAPPDATA%\Programs\JayFlow`,
	}
	for index := range lines {
		if lines[index] != expected[index] {
			return fmt.Errorf("buildinfo.txt line %d is %q, want %q", index+1, lines[index], expected[index])
		}
	}
	return nil
}

func validateSourceIdentity(version, sourceRef, sourceSHA string) error {
	if sourceRef != "v"+version {
		return fmt.Errorf("source ref is %q, want %q", sourceRef, "v"+version)
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(sourceSHA) {
		return errors.New("source SHA must be a lowercase 40-character commit SHA")
	}
	return nil
}

func requireVCSRevision(info *debug.BuildInfo, sourceSHA string) error {
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			if setting.Value != sourceSHA {
				return fmt.Errorf("Go vcs.revision is %q, want %q", setting.Value, sourceSHA)
			}
			return nil
		}
	}
	return errors.New("Go build info has no vcs.revision")
}

func requireEmbeddedBlob(portable, daemon []byte) error {
	if len(daemon) == 0 {
		return errors.New("audited embedded daemon is empty")
	}
	if !bytes.Contains(portable, daemon) {
		return errors.New("portable does not contain the complete audited daemon bytes")
	}
	return nil
}

func auditPE(path string, wantedMachine uint16, wantedVersion [4]uint16) error {
	body, err := readRegularFile(path)
	if err != nil {
		return err
	}
	file, err := pe.NewFile(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("not a PE file: %w", err)
	}
	defer file.Close()
	if wantedMachine != 0 && file.Machine != wantedMachine {
		return fmt.Errorf("machine is %#x, want %#x", file.Machine, wantedMachine)
	}
	if wantedMachine == pe.IMAGE_FILE_MACHINE_AMD64 {
		if _, ok := file.OptionalHeader.(*pe.OptionalHeader64); !ok {
			return errors.New("not a PE32+ executable")
		}
	}
	if err := requireNoAuthenticode(file); err != nil {
		return err
	}
	return verifyFourPartVersion(body, wantedVersion)
}

func requireNoAuthenticode(file *pe.File) error {
	const certificateTable = 4
	var entry pe.DataDirectory
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		entry = header.DataDirectory[certificateTable]
	case *pe.OptionalHeader64:
		entry = header.DataDirectory[certificateTable]
	default:
		return errors.New("PE has no recognized optional header")
	}
	if entry.VirtualAddress != 0 || entry.Size != 0 {
		return errors.New("PE unexpectedly contains an Authenticode certificate table")
	}
	return nil
}

func auditNSIS(path string) error {
	body, err := readRegularFile(path)
	if err != nil {
		return err
	}
	file, err := pe.NewFile(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("not a PE file: %w", err)
	}
	defer file.Close()
	offset, err := peOverlayOffset(file, len(body))
	if err != nil {
		return err
	}
	return verifyNSISFirstHeader(body, offset)
}

func peOverlayOffset(file *pe.File, fileSize int) (int, error) {
	var sizeOfHeaders uint32
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sizeOfHeaders = header.SizeOfHeaders
	case *pe.OptionalHeader64:
		sizeOfHeaders = header.SizeOfHeaders
	default:
		return 0, errors.New("PE has no recognized optional header")
	}
	offset := uint64(sizeOfHeaders)
	for _, section := range file.Sections {
		end := uint64(section.Offset) + uint64(section.Size)
		if end > uint64(fileSize) {
			return 0, fmt.Errorf("PE section %q exceeds file bounds", section.Name)
		}
		if end > offset {
			offset = end
		}
	}
	if offset > uint64(fileSize) {
		return 0, errors.New("PE headers exceed file bounds")
	}
	return int(offset), nil
}

// verifyNSISFirstHeader validates the packed 28-byte firstheader declared by
// NSIS Source/exehead/fileform.h. The total length includes the firstheader
// itself and must consume the complete PE overlay.
func verifyNSISFirstHeader(body []byte, offset int) error {
	const firstHeaderSize = 28
	if offset < 0 || offset > len(body) || len(body)-offset < firstHeaderSize {
		return errors.New("PE has no complete NSIS firstheader at the overlay boundary")
	}
	header := body[offset : offset+firstHeaderSize]
	flags := binary.LittleEndian.Uint32(header[0:4])
	if flags & ^uint32(0x0f) != 0 {
		return fmt.Errorf("NSIS firstheader has unknown flags %#x", flags)
	}
	if binary.LittleEndian.Uint32(header[4:8]) != 0xdeadbeef {
		return errors.New("NSIS firstheader lacks the canonical 0xDEADBEEF signature")
	}
	if !bytes.Equal(header[8:20], []byte("NullsoftInst")) {
		return errors.New("NSIS firstheader lacks the canonical NullsoftInst signature")
	}
	headerLength := binary.LittleEndian.Uint32(header[20:24])
	if headerLength == 0 || headerLength > 1<<31-1 {
		return errors.New("NSIS firstheader has an invalid decompressed header length")
	}
	total := uint64(binary.LittleEndian.Uint32(header[24:28]))
	if total < firstHeaderSize || total != uint64(len(body)-offset) {
		return fmt.Errorf("NSIS overlay length is %d, want %d", total, len(body)-offset)
	}
	return nil
}

func verifyFourPartVersion(body []byte, wanted [4]uint16) error {
	signature := []byte{0xbd, 0x04, 0xef, 0xfe}
	for offset := 0; ; {
		index := bytes.Index(body[offset:], signature)
		if index < 0 {
			break
		}
		index += offset
		if index+24 <= len(body) {
			fileVersion := versionWords(body[index+8 : index+16])
			productVersion := versionWords(body[index+16 : index+24])
			if fileVersion == wanted || productVersion == wanted {
				return nil
			}
		}
		offset = index + len(signature)
	}
	return fmt.Errorf("PE version resource is not %d.%d.%d.%d", wanted[0], wanted[1], wanted[2], wanted[3])
}

func versionWords(body []byte) [4]uint16 {
	first := binary.LittleEndian.Uint32(body[0:4])
	second := binary.LittleEndian.Uint32(body[4:8])
	return [4]uint16{uint16(first >> 16), uint16(first), uint16(second >> 16), uint16(second)}
}

func putVersionWords(body []byte, version [4]uint16) {
	binary.LittleEndian.PutUint32(body[0:4], uint32(version[0])<<16|uint32(version[1]))
	binary.LittleEndian.PutUint32(body[4:8], uint32(version[2])<<16|uint32(version[3]))
}

func requireGoTarget(info *buildinfo.BuildInfo, goos, goarch string) error {
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != goos || settings["GOARCH"] != goarch {
		return fmt.Errorf("Go target is %s/%s, want %s/%s", settings["GOOS"], settings["GOARCH"], goos, goarch)
	}
	if settings["-trimpath"] != "true" {
		return errors.New("Go build is not trimpath")
	}
	return nil
}

func validateVersion(version string) ([3]uint16, error) {
	match := strictVersionPattern.FindStringSubmatch(version)
	if match == nil {
		return [3]uint16{}, errors.New("version must be X.Y.Z or X.Y.Z-dev without leading zeroes")
	}
	var parts [3]uint16
	for index := range parts {
		value, err := strconv.ParseUint(match[index+1], 10, 16)
		if err != nil {
			return [3]uint16{}, fmt.Errorf("Windows version component %q is outside 0..65535", match[index+1])
		}
		parts[index] = uint16(value)
	}
	return parts, nil
}

func validatePortableURL(url, version string) error {
	if url == "" || !strings.HasPrefix(url, "https://") {
		return errors.New("portable URL must use https")
	}
	if !strings.HasSuffix(url, "/JayFlow-"+version+".exe") {
		return errors.New("portable URL does not name the versioned executable")
	}
	return nil
}

func signingPayload(version, digest string) []byte {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	return []byte(updateSigningDomain + "\n" + version + "\n" + strings.ToLower(strings.TrimSpace(digest)) + "\n")
}

func releaseSigningPayload(manifest []byte) []byte {
	return append([]byte(releaseSigningDomain+"\n"), manifest...)
}

func signDetached(private ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(private, payload)
}

func privateKeyFromEnv() (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(os.Getenv(privateKeyEnv))
	if err != nil {
		return nil, fmt.Errorf("$%s is not base64: %w", privateKeyEnv, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("$%s is %d bytes, want %d", privateKeyEnv, len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be base64 encoding of %d bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func unsignedAssetNames(version string) []string {
	return []string{
		"JayFlow-" + version + ".exe",
		"JayFlow-" + version + "-setup.exe",
		"JayFlow-setup.exe",
		"buildinfo.txt",
	}
}

func signedAssetNames(version string) []string {
	names := append([]string{}, unsignedAssetNames(version)...)
	return append(names, latestName, releaseManifestName, releaseSignatureName, checksumsName)
}

func checksumCoveredNames(version string) []string {
	names := append([]string{}, unsignedAssetNames(version)...)
	return append(names, latestName, releaseManifestName, releaseSignatureName)
}

func requireExactInventory(dir string, expected []string) error {
	if err := requireDirectory(dir); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		if err := requireRegularFile(filepath.Join(dir, entry.Name())); err != nil {
			return fmt.Errorf("asset %q: %w", entry.Name(), err)
		}
		actual = append(actual, entry.Name())
	}
	sort.Strings(actual)
	want := append([]string{}, expected...)
	sort.Strings(want)
	if !equalStrings(actual, want) {
		return fmt.Errorf("asset inventory is %q, want %q", actual, want)
	}
	return nil
}

func requireIdenticalInstallers(dir, version string) error {
	versioned, err := readRegularFile(filepath.Join(dir, "JayFlow-"+version+"-setup.exe"))
	if err != nil {
		return err
	}
	stable, err := readRegularFile(filepath.Join(dir, "JayFlow-setup.exe"))
	if err != nil {
		return err
	}
	if !bytes.Equal(versioned, stable) {
		return errors.New("stable and versioned setup names do not contain identical bytes")
	}
	return nil
}

func hashFile(path string) (string, int64, error) {
	handle, err := openRegularFile(path)
	if err != nil {
		return "", 0, err
	}
	defer handle.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, handle)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func generateChecksums(dir, version string) ([]byte, error) {
	var body strings.Builder
	for _, name := range checksumCoveredNames(version) {
		digest, _, err := hashFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&body, "%s  %s\n", digest, name)
	}
	return []byte(body.String()), nil
}

func validDigest(digest string) bool {
	if len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == sha256.Size
}

func marshalJSON(value any) ([]byte, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func writeJSON(path string, value any) error {
	body, err := marshalJSON(value)
	if err != nil {
		return err
	}
	return writeNewRegularFile(path, body, 0o644)
}

func requireDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory without symlinks", path)
	}
	return nil
}

func requireRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}

func readRegularFile(path string) ([]byte, error) {
	handle, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	return io.ReadAll(handle)
}

func openRegularFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := handle.Stat()
	if err != nil {
		handle.Close()
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		handle.Close()
		return nil, err
	}
	if !opened.Mode().IsRegular() || !after.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) {
		handle.Close()
		return nil, fmt.Errorf("%s changed while being opened as a regular file", path)
	}
	return handle, nil
}

func writeNewRegularFile(path string, body []byte, mode os.FileMode) error {
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("refusing to replace existing output %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	handle, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	written := false
	defer func() {
		if !written {
			_ = handle.Close()
		}
	}()
	info, err := handle.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("new output %s is not a regular file", path)
	}
	if _, err := handle.Write(body); err != nil {
		return err
	}
	if err := handle.Close(); err != nil {
		return err
	}
	written = true
	return requireRegularFile(path)
}

func decodeStrictJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	return bytes.Equal(left, right)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
