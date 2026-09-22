// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/siderolabs/talos/pkg/machinery/overlay"
	"github.com/siderolabs/talos/pkg/machinery/overlay/adapter"
	"golang.org/x/sys/unix"
)

const (
	off   int64 = 512 * 64
	board       = "rockpi4c"

	// Artifacts-relative device tree paths (see installers/pkg.yaml, which
	// bundles the base DTB and the radxa-overlays .dtbo files into the overlay
	// image). The imager merges the overlays with its own bundled fdtoverlay.
	baseDTB     = "arm64/dtb/rockchip/rk3399-rock-pi-4c.dtb"
	overlaysDir = "arm64/dtb/rockchip/overlays"

	// uBootDir is the artifacts-relative root under which each u-boot build lives,
	// in a "<board>[-<variant>]" subdirectory (see artifacts/pkg.yaml). A variant
	// may ship matching device tree overlays under its overlays/ subdirectory.
	uBootDir = "arm64/u-boot"

	// uBootToolsDir holds the u-boot host tools the FIT signing path runs:
	// fdt_add_pubkey, mkimage and fit_check_sign. They come out of the same
	// u-boot build the firmware does, so they match the images they operate on.
	// They are shipped once for the board rather than per variant, since both
	// variants are built from one source tree.
	//
	// The u-boot package is pinned to linux/arm64 (see installers/pkg.yaml), so
	// these are arm64 binaries: signing needs the imager to be running on arm64.
	// The default, unsigned path shells out to nothing and is unaffected.
	uBootToolsDir = "arm64/u-boot-tools/rockpi4c"

	// partitionOffsetSectors is how far out the first partition is pushed to
	// leave room for the boot blob, in sectors.
	partitionOffsetSectors = 2048 * 10

	// firstPartitionOffset is the same bound in bytes. A sector is at least 512
	// bytes, so this is the lowest the first partition can start and therefore
	// the safe limit for the boot blob to stay under.
	firstPartitionOffset int64 = partitionOffsetSectors * 512
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	adapter.Execute(ctx, &rockPi4c{})
}

type rockPi4c struct{}

type rockPi4cExtraOptions struct {
	// DTOverlays is a comma-separated list of overlay names shipped in the
	// artifacts (radxa-overlays .dtbo basenames), applied to the base DTB.
	DTOverlays string `yaml:"dtOverlays,omitempty"`
	// DTOverlaysInline is a comma-separated list of base64-encoded overlays
	// applied to the base DTB, for overlays maintained locally and passed at
	// build time rather than shipped in the artifacts. Each entry is a .dts
	// source (compiled by the imager) or a precompiled .dtbo; base64 only shields
	// the blob from the CLI/profile string transport.
	DTOverlaysInline string `yaml:"dtOverlaysInline,omitempty"`
	// UBootVariant selects a non-default u-boot build shipped by this overlay,
	// found under arm64/u-boot/<board>-<variant>. The default ("") uses the
	// board's stock u-boot. A variant may bundle matching device tree overlays
	// under its overlays/ directory, which are merged into the measured UKI DTB
	// so the kernel's view of the hardware matches u-boot's control DTB. E.g. the
	// "spi-tpm" variant drives an external SPI TPM (letting u-boot measure the UKI
	// into PCR 11) and repurposes spi1 from the SPI-NOR flash to the TPM. Kept
	// generic on purpose: the installer only selects a u-boot variant, it encodes
	// nothing TPM-specific. A string so it decodes the same whether passed as a
	// CLI --overlay-option (always a string) or in a profile's overlay options.
	UBootVariant string `yaml:"uBootVariant,omitempty"`
	// FITSigningKey turns on SPL verification of the u-boot FIT and says where
	// the signing key comes from. The default ("") writes the u-boot image the
	// artifacts ship, untouched and unsigned. "ephemeral" makes the image build
	// generate a throwaway key, sign the FIT with it and pin its public half in
	// the SPL control device tree, so the SPL will only load the FIT it was
	// written to the disk with. Naming the key source rather than taking a
	// boolean leaves room for the key the rk3399 eFuse will eventually pin,
	// which has to be the user's and outlive the image build.
	FITSigningKey string `yaml:"fitSigningKey,omitempty"`
}

func (i *rockPi4c) GetOptions(_ context.Context, extra rockPi4cExtraOptions) (overlay.Options, error) {
	options := overlay.Options{
		Name: board,
		KernelArgs: []string{
			"console=tty0",
			"console=ttyS2,1500000n8",
			"sysctl.kernel.kexec_load_disabled=1",
			"talos.dashboard.disabled=1",
		},
		PartitionOptions: overlay.PartitionOptions{
			Offset: partitionOffsetSectors,
		},
		// Embed the (measured) base device tree in the UKI. Board overlays are
		// opt-in via the dtOverlays extra option and merged on top at image
		// build time, so they end up inside the signed and measured UKI.
		DeviceTree: baseDTB,
	}

	options.DeviceTreeOverlays = deviceTreeOverlays(extra.DTOverlays)

	// Every u-boot variant bundles the kernel overlays that describe what the
	// firmware it ships changes under its artifacts overlays/ directory; merge
	// them into the measured UKI DTB so the kernel and the firmware agree. The
	// imager applies every .dtbo in the directory, so a variant can ship a set
	// without naming each, and a variant with nothing to describe ships none.
	variantDir := board
	if extra.UBootVariant != "" {
		variantDir += "-" + extra.UBootVariant
	}

	options.DeviceTreeOverlays = append(options.DeviceTreeOverlays,
		filepath.Join(uBootDir, variantDir, "overlays"))

	dtOverlaysInline, err := deviceTreeOverlaysInline(extra.DTOverlaysInline)
	if err != nil {
		return overlay.Options{}, err
	}

	options.DeviceTreeOverlaysInline = dtOverlaysInline

	return options, nil
}

// deviceTreeOverlaysInline decodes a comma-separated list of base64-encoded
// overlays passed at build time. Each decoded blob is a .dts source or a
// precompiled .dtbo; the imager tells them apart and compiles source as needed.
func deviceTreeOverlaysInline(dtOverlaysInline string) ([][]byte, error) {
	var overlays [][]byte

	for _, b64 := range strings.Split(dtOverlaysInline, ",") {
		if b64 = strings.TrimSpace(b64); b64 == "" {
			continue
		}

		blob, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("invalid inline device tree overlay: %w", err)
		}

		overlays = append(overlays, blob)
	}

	return overlays, nil
}

// deviceTreeOverlays maps a comma-separated list of overlay names (radxa-overlays
// .dtbo basenames, e.g. "rk3399-spi1-spidev") to their artifacts-relative
// .dtbo paths.
func deviceTreeOverlays(dtOverlays string) []string {
	var overlays []string

	for _, name := range strings.Split(dtOverlays, ",") {
		if name = strings.TrimSpace(name); name != "" {
			overlays = append(overlays, filepath.Join(overlaysDir, name+".dtbo"))
		}
	}

	return overlays
}

func (i *rockPi4c) Install(ctx context.Context, options overlay.InstallOptions[rockPi4cExtraOptions]) error {
	uBootBoard := board
	if options.ExtraOptions.UBootVariant != "" {
		uBootBoard = board + "-" + options.ExtraOptions.UBootVariant
	}

	uBoot := filepath.Join(options.ArtifactsPath, uBootDir, uBootBoard)

	// Secure Boot keys, if this image build was given any. They are enrolled by
	// rewriting u-boot, which is a payload of the FIT the SPL verifies, so doing
	// it means signing the FIT afterwards whether that was asked for or not.
	variables, err := secureBootVariables(secureBootDir)
	if err != nil {
		return err
	}

	key, err := newFITSigningKey(options.ExtraOptions.FITSigningKey)
	if err != nil {
		return err
	}

	if key == nil && len(variables) > 0 {
		key = ephemeralKey{}
	}

	var image []byte

	if key == nil {
		// Nothing to sign and nothing to enrol: write the image the u-boot package
		// packed, as it packed it.
		image, err = os.ReadFile(filepath.Join(uBoot, "u-boot-rockchip.bin"))
	} else {
		image, err = signedUBoot(ctx, filepath.Join(options.ArtifactsPath, uBootToolsDir), uBoot, key, variables)
	}

	if err != nil {
		return err
	}

	return uBootLoaderInstall(image, options.InstallDisk)
}

func uBootLoaderInstall(uboot []byte, installDisk string) error {
	// Signing grows the image, so check it still clears the first partition
	// rather than let it corrupt one.
	if end := off + int64(len(uboot)); end > firstPartitionOffset {
		return fmt.Errorf("the boot blob ends at %d, past the first partition at %d", end, firstPartitionOffset)
	}

	f, err := os.OpenFile(installDisk, unix.O_RDWR|unix.O_CLOEXEC, 0o666)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", installDisk, err)
	}

	defer f.Close() //nolint:errcheck

	if _, err = f.WriteAt(uboot, off); err != nil {
		return err
	}

	// NB: In the case that the block device is a loopback device, we sync here
	// to ensure that the file is written before the loopback device is
	// unmounted.
	return f.Sync()
}
