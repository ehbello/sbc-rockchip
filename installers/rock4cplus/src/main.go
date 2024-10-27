// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/siderolabs/go-copy/copy"
	"github.com/siderolabs/talos/pkg/machinery/overlay"
	"github.com/siderolabs/talos/pkg/machinery/overlay/adapter"
	"golang.org/x/sys/unix"
)

const (
	off   int64 = 512 * 64
	board       = "rock4cplus"
	// https://github.com/u-boot/u-boot/blob/abd4fb5ac13215733569925a06991e0a182ede14/configs/rock-4c-plus-rk3399_defconfig#L22
	fdtfile     = "rk3399-rock-4c-plus.dtb"
	dtbdir      = "dtb/rockchip"
)

// List of boot files to copy
var bootFiles = []string{
	filepath.Join(dtbdir, fdtfile),
	"boot.scr",
}

func main() {
	adapter.Execute(&rock4cplus{})
}

type rock4cplus struct{}

type rock4cplusExtraOptions struct {
	DTOverlays string `yaml:"dtOverlays,omitempty"`
}

func (i *rock4cplus) GetOptions(extra rock4cplusExtraOptions) (overlay.Options, error) {
	return overlay.Options{
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
	}, nil
}

func (i *rock4cplus) Install(options overlay.InstallOptions[rock4cplusExtraOptions]) error {
	var f *os.File

	f, err := os.OpenFile(options.InstallDisk, os.O_RDWR|unix.O_CLOEXEC, 0o666)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", options.InstallDisk, err)
	}

	defer f.Close() //nolint:errcheck

	uboot, err := os.ReadFile(filepath.Join(options.ArtifactsPath, "arm64/u-boot", board, "u-boot-rockchip.bin"))
	if err != nil {
		return err
	}

	if _, err = f.WriteAt(uboot, off); err != nil {
		return err
	}

	// NB: In the case that the block device is a loopback device, we sync here
	// to esure that the file is written before the loopback device is
	// unmounted.
	err = f.Sync()
	if err != nil {
		return err
	}

	if dtOverlays := options.ExtraOptions.DTOverlays; dtOverlays != "" {
		talosEnvPath := filepath.Join(options.MountPrefix, "/boot/EFI/boot.env")
		talosEnvFile, err := os.OpenFile(talosEnvPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", talosEnvPath, err)
		}
		defer talosEnvFile.Close()

		overlaysLine := fmt.Sprintf("overlays=%s\n", dtOverlays)
		if _, err := talosEnvFile.WriteString(overlaysLine); err != nil {
			return fmt.Errorf("failed to write env to %s: %w", talosEnvPath, err)
		}

		for _, overlayName := range strings.Fields(dtOverlays) {
			bootFiles = append(bootFiles, filepath.Join(dtbdir, "overlays", overlayName+".dtbo"))
		}
	}

	for _, bootFile := range bootFiles {
		src := filepath.Join(options.ArtifactsPath, "arm64/", bootFile)
		dst := filepath.Join(options.MountPrefix, "/boot/EFI/", bootFile)

		err = os.MkdirAll(filepath.Dir(dst), 0o755)
		if err != nil {
			return err
		}

		err = copy.File(src, dst)
		if err != nil {
			return err
		}
	}

	return nil
}
