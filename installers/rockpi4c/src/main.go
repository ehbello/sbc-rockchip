// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"encoding/base64"
	_ "embed"
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
			Offset: 2048 * 10,
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

func (i *rockPi4c) Install(_ context.Context, options overlay.InstallOptions[rockPi4cExtraOptions]) error {
	uBootBoard := board
	if options.ExtraOptions.UBootVariant != "" {
		uBootBoard = board + "-" + options.ExtraOptions.UBootVariant
	}

	uBootBin := filepath.Join(options.ArtifactsPath, uBootDir, uBootBoard, "u-boot-rockchip.bin")

	return uBootLoaderInstall(uBootBin, options.InstallDisk)
}

func uBootLoaderInstall(uBootBin, installDisk string) error {
	f, err := os.OpenFile(installDisk, unix.O_RDWR|unix.O_CLOEXEC, 0o666)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", installDisk, err)
	}

	defer f.Close() //nolint:errcheck

	uboot, err := os.ReadFile(uBootBin)
	if err != nil {
		return err
	}

	if _, err = f.WriteAt(uboot, off); err != nil {
		return err
	}

	// NB: In the case that the block device is a loopback device, we sync here
	// to ensure that the file is written before the loopback device is
	// unmounted.
	return f.Sync()
}
