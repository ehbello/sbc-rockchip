// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Verified boot of the u-boot FIT.
//
// CONFIG_SPL_FIT_SIGNATURE only makes the SPL *able* to check the FIT it loads.
// It becomes an enforced check once two things are true: the SPL control
// devicetree declares a required key, and the FIT carries a signature made with
// it. Signing a configuration covers the hash nodes of the images it names, so
// one signature binds TF-A's BL31, u-boot proper and the devicetree together;
// the SPL then checks those hashes against the payloads as it loads them.
//
// This happens here, at image build time, rather than in the u-boot package,
// for two reasons. A key generated during the package build would make the
// published overlay image differ from one CI run to the next, and this project
// verifies artifacts by content hash. And the key belongs on the user's side:
// once the rk3399 eFuse pins the boot loader, it has to be a key the user keeps,
// not one a public build produced.
//
// The signature does not make the board secure on its own. Nothing yet stops an
// attacker from replacing the SPL and the FIT as a pair, because the mask ROM
// does not check the SPL. What it buys today is that the SPL refuses a
// u-boot.itb it was not built with, so the FIT can no longer be swapped or
// edited in place on the boot medium.

const (
	// fitSigningKeyEphemeral generates a throwaway key for this image build.
	fitSigningKeyEphemeral = "ephemeral"

	// fitSignAlgo is the signature algorithm, in the spelling u-boot uses for
	// both the FIT's "algo" property and the -a flag of its tools.
	fitSignAlgo = "sha256,rsa2048"

	// fitSignKeyBits must match fitSignAlgo.
	fitSignKeyBits = 2048

	// fitSignKeyName names the key in the FIT ("key-name-hint") and in the SPL
	// control devicetree (/signature/key-<name>), and is the basename of the
	// .key and .crt files the u-boot tools read.
	fitSignKeyName = "spl-fit"

	// socName is what mkimage calls this SoC when it builds a Rockchip ID block
	// (CONFIG_SYS_SOC, which binman passes to mkimage -n).
	socName = "rk3399"

	// fitExternalAlign is the alignment of the FIT's external payloads, as
	// mkimage -B takes it: hexadecimal, and 0x200 is the fit,align binman asks
	// for in arch/arm/dts/rockchip-u-boot.dtsi.
	fitExternalAlign = "200"

	// Devicetree header fields, see the Devicetree Specification v0.4 section 5.2.
	fdtTotalSizeOffset = 4
	fdtHeaderSize      = 40
)

// fitSignImages names the image classes a configuration signature covers. These
// are the properties of the configuration that point at images, so the signature
// ends up covering every payload the SPL loads.
var fitSignImages = []string{"firmware", "loadables", "fdt"}

// fitSigningKey supplies the RSA key pair that signs the FIT and whose public
// half is pinned in the SPL control devicetree.
//
// It is an interface because the key has to come from somewhere else eventually:
// a board whose eFuse pins the boot loader can only be signed with the key that
// eFuse burned, which is the user's and is handed to the image build the way the
// imager is already handed a secure boot signer. Only newFITSigningKey knows
// which kind of key is in use; nothing downstream of it does.
type fitSigningKey interface {
	// write materialises the key pair in dir as "<name>.key", a PEM private key,
	// and "<name>.crt", a PEM certificate. That side by side pair is the layout
	// mkimage -k and fdt_add_pubkey -k look for; the tools read the public half
	// out of the certificate and never look at its validity dates.
	write(dir, name string) error
}

// newFITSigningKey maps the fitSigningKey extra option to a key source. The
// empty option asks for no signing at all and returns a nil key.
func newFITSigningKey(option string) (fitSigningKey, error) {
	switch option {
	case "":
		return nil, nil
	case fitSigningKeyEphemeral:
		return ephemeralKey{}, nil
	default:
		return nil, fmt.Errorf("unknown fitSigningKey %q, expected %q or an empty value", option, fitSigningKeyEphemeral)
	}
}

// ephemeralKey generates a key pair for this image build and nothing else.
//
// The SPL and the FIT it verifies are written to the disk as one blob and are
// always flashed together, so a key that exists only for the duration of the
// image build is self-consistent: the SPL carries the public half in its own
// devicetree. That means no key management and no secrets in CI, at the cost of
// two things. The FIT can no longer be updated on its own (the `fastboot flash
// loader2` flow, which this board does not use), and two images built from the
// same inputs are no longer bit-identical.
type ephemeralKey struct{}

func (ephemeralKey) write(dir, name string) error {
	key, err := rsa.GenerateKey(rand.Reader, fitSignKeyBits)
	if err != nil {
		return fmt.Errorf("failed to generate a FIT signing key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to encode the FIT signing key: %w", err)
	}

	if err = writePEM(filepath.Join(dir, name+".key"), "PRIVATE KEY", der); err != nil {
		return err
	}

	// The certificate is only a container for the public half, so it is
	// self-signed and its dates are fixed rather than taken from the clock.
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Rock Pi 4C ephemeral FIT signing key"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<31-1, 0),
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to certify the FIT signing key: %w", err)
	}

	return writePEM(filepath.Join(dir, name+".crt"), "CERTIFICATE", cert)
}

func writePEM(path, blockType string, der []byte) error {
	block := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})

	if err := os.WriteFile(path, block, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	return nil
}

// signedUBoot rebuilds the board's boot blob with SPL FIT verification enforced
// and returns the bytes to write to the disk.
//
// The order of the steps is forced by the way the pieces nest. The SPL control
// devicetree is packed inside the Rockchip ID block, so the public key has to be
// in it before that block is rebuilt; the FIT is signed separately and sits
// after it in the blob.
func signedUBoot(ctx context.Context, tools, uBoot string, key fitSigningKey) ([]byte, error) {
	// Everything else this runs is resolved under the artifacts path, where the
	// u-boot package puts it. These two come from the imager instead; look them
	// up now so a missing one is reported as itself rather than as whatever step
	// happens to reach it first.
	for _, tool := range []string{"fdtget", "fdtput"} {
		if _, err := exec.LookPath(tool); err != nil {
			return nil, fmt.Errorf("signing the FIT needs %s from the imager's dtc package: %w", tool, err)
		}
	}

	work, err := os.MkdirTemp("", "rockpi4c-fit-")
	if err != nil {
		return nil, fmt.Errorf("failed to create a work directory: %w", err)
	}

	defer os.RemoveAll(work) //nolint:errcheck

	keyDir := filepath.Join(work, "key")
	if err = os.Mkdir(keyDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create a key directory: %w", err)
	}

	if err = key.write(keyDir, fitSignKeyName); err != nil {
		return nil, err
	}

	splDTB, err := pinPublicKey(ctx, tools, uBoot, work, keyDir)
	if err != nil {
		return nil, err
	}

	idbloader, err := rebuildIDBlock(ctx, tools, uBoot, work, splDTB)
	if err != nil {
		return nil, err
	}

	fit, offset, err := signFIT(ctx, tools, uBoot, work, keyDir, splDTB)
	if err != nil {
		return nil, err
	}

	return packRockchipImage(idbloader, fit, offset)
}

// pinPublicKey writes the public half of the key into the SPL control
// devicetree, marked as required. That property is what makes the SPL reject a
// configuration the key does not cover, rather than wave it through.
func pinPublicKey(ctx context.Context, tools, uBoot, work, keyDir string) (string, error) {
	splDTB := filepath.Join(work, "u-boot-spl.dtb")

	if err := copyFile(filepath.Join(uBoot, "u-boot-spl.dtb"), splDTB); err != nil {
		return "", err
	}

	if _, err := run(ctx, filepath.Join(tools, "fdt_add_pubkey"),
		"-a", fitSignAlgo, "-k", keyDir, "-n", fitSignKeyName, "-r", "conf", splDTB); err != nil {
		return "", err
	}

	return splDTB, nil
}

// rebuildIDBlock rebuilds the Rockchip ID block around the keyed SPL control
// devicetree, the way binman's mkimage entry in
// arch/arm/dts/rockchip-u-boot.dtsi builds it.
func rebuildIDBlock(ctx context.Context, tools, uBoot, work, splDTB string) ([]byte, error) {
	// The SPL binary is the SPL proper followed by its control devicetree, so
	// swapping the devicetree means replacing that tail. Deriving the split from
	// the two published files rather than from a configured size keeps it exact
	// whatever u-boot puts between them.
	spl, err := os.ReadFile(filepath.Join(uBoot, "u-boot-spl.bin"))
	if err != nil {
		return nil, err
	}

	dtb, err := os.ReadFile(filepath.Join(uBoot, "u-boot-spl.dtb"))
	if err != nil {
		return nil, err
	}

	prefix, found := bytes.CutSuffix(spl, dtb)
	if !found {
		return nil, fmt.Errorf("u-boot-spl.bin does not end in u-boot-spl.dtb")
	}

	keyed, err := os.ReadFile(splDTB)
	if err != nil {
		return nil, err
	}

	splBin := filepath.Join(work, "u-boot-spl.bin")
	if err = os.WriteFile(splBin, slices.Concat(prefix, keyed), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write %s: %w", splBin, err)
	}

	return mkIDBlock(ctx, tools, filepath.Join(work, "idbloader.img"),
		filepath.Join(uBoot, "u-boot-tpl.bin"), splBin)
}

// mkIDBlock runs mkimage the way binman does for the eMMC/SD image: an "rksd"
// ID block over the TPL and the SPL, passed as multiple data files.
func mkIDBlock(ctx context.Context, tools, idbloader, tpl, spl string) ([]byte, error) {
	// The SPI-NOR image binman also builds uses "rkspi" here. The installer only
	// ever writes the eMMC/SD image, so that one is left to the artifacts.
	if _, err := run(ctx, filepath.Join(tools, "mkimage"),
		"-n", socName, "-T", "rksd", "-d", tpl+":"+spl, idbloader); err != nil {
		return nil, err
	}

	return os.ReadFile(idbloader)
}

// signFIT signs the published FIT and returns it along with the offset it is
// packed at.
func signFIT(ctx context.Context, tools, uBoot, work, keyDir, splDTB string) ([]byte, int, error) {
	fit, err := os.ReadFile(filepath.Join(uBoot, "u-boot.itb"))
	if err != nil {
		return nil, 0, err
	}

	packed, err := os.ReadFile(filepath.Join(uBoot, "u-boot-rockchip.bin"))
	if err != nil {
		return nil, 0, err
	}

	offset, err := packedFITOffset(ctx, tools, uBoot, work, packed, fit)
	if err != nil {
		return nil, 0, err
	}

	path := filepath.Join(work, "u-boot.itb")
	if err = os.WriteFile(path, fit, 0o600); err != nil {
		return nil, 0, fmt.Errorf("failed to write %s: %w", path, err)
	}

	if err = addConfigSignatures(ctx, path); err != nil {
		return nil, 0, err
	}

	// -E and -B are the flags binman itself passes; -t, which it also passes, is
	// left out so that the FIT keeps the timestamp the u-boot package gave it.
	// Without -k and -r this call is a byte for byte no-op on what binman packed.
	if _, err = run(ctx, filepath.Join(tools, "mkimage"),
		"-E", "-B", fitExternalAlign, "-k", keyDir, "-r", "-F", path); err != nil {
		return nil, 0, err
	}

	// fit_check_sign is the verifier the SPL runs, built from the same source.
	// Refuse to write an image the SPL would reject.
	if _, err = run(ctx, filepath.Join(tools, "fit_check_sign"), "-f", path, "-k", splDTB); err != nil {
		return nil, 0, fmt.Errorf("the signed FIT does not verify against the SPL devicetree: %w", err)
	}

	signed, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	return signed, offset, nil
}

// packedFITOffset finds the offset the FIT is packed at in the image the u-boot
// package publishes, and checks that the rest of that image is nothing but the
// ID block on a 0xff background.
//
// The offset is CONFIG_SPL_PAD_TO, but reading it back out of the published
// image avoids publishing the value separately, and turns the layout
// packRockchipImage assumes into something checked rather than believed: if a
// u-boot upgrade moves anything, the mismatch shows up here instead of in a
// board that does not boot.
func packedFITOffset(ctx context.Context, tools, uBoot, work string, packed, fit []byte) (int, error) {
	offset := len(packed) - len(fit)

	if offset <= 0 || !bytes.Equal(packed[offset:], fit) {
		return 0, fmt.Errorf("u-boot-rockchip.bin does not end in u-boot.itb")
	}

	idbloader, err := mkIDBlock(ctx, tools, filepath.Join(work, "idbloader-published.img"),
		filepath.Join(uBoot, "u-boot-tpl.bin"), filepath.Join(uBoot, "u-boot-spl.bin"))
	if err != nil {
		return 0, err
	}

	repacked, err := packRockchipImage(idbloader, fit, offset)
	if err != nil {
		return 0, err
	}

	if !bytes.Equal(repacked, packed) {
		return 0, fmt.Errorf("reassembling u-boot-rockchip.bin from its pieces does not reproduce it")
	}

	return offset, nil
}

// addConfigSignatures adds an empty signature node to every configuration of the
// FIT at path. mkimage fills signature nodes in, it does not create them:
// image-host.c only walks the "signature" subnodes it finds, so they have to
// exist before it is asked to sign.
//
// fdtput and fdtget come from the imager, not from the artifacts. They are part
// of the same dtc package as the fdtoverlay this board already depends on -- the
// imager runs it to merge the device tree overlays a u-boot variant ships into
// the measured UKI device tree -- so requiring them costs nothing beyond what is
// required already.
//
// fdtput writes back only the devicetree, dropping whatever followed it in the
// file, so the FIT's external payloads are split off first and appended again
// afterwards. Their data-offset properties are relative to the end of the
// devicetree rounded up to four bytes, so putting them back at that same
// boundary is what lets the devicetree grow underneath them.
func addConfigSignatures(ctx context.Context, path string) error {
	fit, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if len(fit) < fdtHeaderSize {
		return fmt.Errorf("%s is %d bytes, too short to hold a devicetree header", path, len(fit))
	}

	size := int(binary.BigEndian.Uint32(fit[fdtTotalSizeOffset:]))
	if size < fdtHeaderSize || align4(size) > len(fit) {
		return fmt.Errorf("%s declares a %d byte devicetree, out of range for a %d byte file", path, size, len(fit))
	}

	tree, payloads := path+".fdt", fit[align4(size):]

	if err = os.WriteFile(tree, fit[:size], 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", tree, err)
	}

	defer os.Remove(tree) //nolint:errcheck

	configs, err := run(ctx, "fdtget", "-l", tree, "/configurations")
	if err != nil {
		return err
	}

	names := strings.Fields(string(configs))
	if len(names) == 0 {
		return fmt.Errorf("%s has no configuration to sign", path)
	}

	for _, name := range names {
		node := "/configurations/" + name + "/signature"

		for _, args := range [][]string{
			{"-c", tree, node},
			{"-t", "s", tree, node, "algo", fitSignAlgo},
			{"-t", "s", tree, node, "key-name-hint", fitSignKeyName},
			append([]string{"-t", "s", tree, node, "sign-images"}, fitSignImages...),
		} {
			if _, err = run(ctx, "fdtput", args...); err != nil {
				return err
			}
		}
	}

	// fdtput writes exactly fdt_totalsize bytes, so the file it leaves behind is
	// the whole devicetree and nothing else.
	edited, err := os.ReadFile(tree)
	if err != nil {
		return err
	}

	out := make([]byte, 0, align4(len(edited))+len(payloads))
	out = append(out, edited...)
	out = append(out, make([]byte, align4(len(edited))-len(edited))...)
	out = append(out, payloads...)

	if err = os.WriteFile(path, out, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	return nil
}

// packRockchipImage lays out a Rockchip boot blob: the ID block at offset 0, the
// FIT at a fixed offset, 0xff in between.
func packRockchipImage(idbloader, fit []byte, offset int) ([]byte, error) {
	if len(idbloader) > offset {
		return nil, fmt.Errorf("the %d byte ID block does not fit before the FIT at %d", len(idbloader), offset)
	}

	image := make([]byte, offset, offset+len(fit))
	for i := range image {
		image[i] = 0xff
	}

	copy(image, idbloader)

	return append(image, fit...), nil
}

func copyFile(from, to string) error {
	content, err := os.ReadFile(from)
	if err != nil {
		return err
	}

	if err = os.WriteFile(to, content, 0o600); err != nil {
		return fmt.Errorf("failed to write %s: %w", to, err)
	}

	return nil
}

// run executes one of the tools the signing path drives and returns what it
// printed.
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w: %s", filepath.Base(name), err, bytes.TrimSpace(out))
	}

	return out, nil
}

// align4 rounds up to the four byte boundary a devicetree ends on.
func align4(n int) int {
	return (n + 3) &^ 3
}
