# sbc-rockchip

This repo provides the overlay for RockChip based Talos image.

## Supported Overlay

| Overlay Name            | Board                   | SoC     | Description                                    |
| ----------------------- | ----------------------- | ------- | ---------------------------------------------- |
| friendlyelec-cm3588-nas | FriendlyElec CM3588 NAS | RK3588  | Overlay for FriendlyElec CM3588 NAS / NAS Plus |
| helios64                | Kobol Helios64          | RK3399  | Overlay for Kobol Helios64                     |
| nanopi-r4s              | NanoPi R4S              | RK3399  | Overlay for NanoPi R4S                         |
| nanopi-r5s              | NanoPi R5S              | RK3568  | Overlay for NanoPi R5S (only WAN, no NVMe)     |
| odroid-m1               | Hardkernel Odroid M1    | RK3568  | Overlay for Hardkernel's Odroid M1             |
| orangepi-5              | Orange Pi 5             | RK3588s | Overlay for Orange Pi 5                        |
| orangepi-5-max          | Orange Pi 5 Max         | RK3588  | Overlay for Orange Pi 5 Max                    |
| orangepi-5-plus         | Orange Pi 5 Plus        | RK3588  | Overlay for Orange Pi 5 Plus                   |
| orangepi-r1-plus-lts    | Orange Pi R1 Plus LTS   | RK3328  | Overlay for Orange Pi R1 Plus LTS              |
| radxa-zero-3e           | Radxa ZERO 3E           | RK3566  | Overlay for Radxa ZERO 3E                      |
| rock3b                  | Radxa ROCK 3B           | RK3568  | Overlay for Radxa ROCK 3B                      |
| rock4cplus              | Radxa ROCK 4C+          | RK3399  | Overlay for Radxa ROCK 4C+                     |
| rock4se                 | Rock 4 SE               | RK3399  | Overlay for Rock 4 SE                          |
| rock5a                  | Radxa ROCK 5A           | RK3588s | Overlay for Radxa ROCK 5A                      |
| rock5b                  | Radxa ROCK 5B           | RK3588  | Overlay for Radxa ROCK 5B                      |
| rock5b-plus             | Radxa ROCK 5B+          | RK3588  | Overlay for Radxa ROCK 5B+                     |
| rock5t                  | Radxa ROCK 5T           | RK3588  | Overlay for Radxa ROCK 5T                      |
| rock64                  | Pine64 Rock64           | RK3328  | Overlay for Pine64 Rock64                      |
| rockpi4                 | Rock Pi 4A,Rock Pi 4B   | RK3399  | Generic overlay for Rock Pi 4A and Rock Pi 4B  |
| rockpi4c                | Rock Pi 4C              | RK3399  | Overlay for Rock Pi 4C                         |
| rockpro64               | Pine64 ROCKPro64        | RK3399  | Overlay for Pine64 ROCKPro64                   |
| turingrk1               | Turing Machines RK1     | RK3588  | Overlay for Turing Machines RK1                |

## Rock Pi 4C trusted boot

The `rockpi4c` overlay builds three u-boot variants, selected with the
`uBootVariant` overlay option. Two of them give u-boot a TPM, which is what makes
it expose `EFI_TCG2_PROTOCOL` so systemd-stub measures the UKI into PCR 11, the
PCR Talos seals disk encryption keys to. They differ in where that TPM comes
from: soldered to the board, or synthesised by firmware.

| `uBootVariant` | TPM                                    | Hardware needed             | SPI-NOR boot |
| -------------- | -------------------------------------- | --------------------------- | ------------ |
| (unset)        | none                                   | none                        | preserved    |
| `spi-tpm`      | discrete TPM 2.0 on soft-SPI (spi1)    | e.g. Infineon SLB9670       | unavailable  |
| `ftpm`         | firmware TPM inside OP-TEE             | none                        | preserved    |

`ftpm` is opt-in and deliberately not the default: read the limitations below
before choosing it. It is the only variant that loads a secure world -- the only
one built with `TEE=`, the only one whose control device tree describes OP-TEE,
and the only one that reserves the 36 MiB of DRAM OP-TEE owns. The other two are
byte for byte what they were before this variant existed.

One thing does reach them. BL31 is built once for the SoC and now carries the
OP-TEE dispatcher (`SPD=opteed`), because the `ftpm` variant needs it. On the
other two there is no BL32 for that dispatcher to find, so they log this and
carry on booting normally:

```console
WARNING: No OPTEE provided by BL2 boot loader, Booting device without OPTEE initialization. SMC`s destined for OPTEE will return SMC_UNK
ERROR:   Error initializing runtime service opteed_fast
```

Nothing in those variants asks for an OP-TEE service, so that is the whole
effect: expected output rather than a fault to chase.

### Known limitations of the firmware TPM

* **Linux cannot use it.** The fTPM is reached over the OP-TEE driver, and the
  Talos kernel is built with `# CONFIG_TEE is not set`, so `tpm_ftpm_tee` does
  not exist and no `/dev/tpm*` appears. The fTPM still works in firmware -- it
  is what populates PCR 11 before Linux starts -- but nothing in userspace can
  talk to it, which means Talos cannot seal or unseal against it. Fixing this
  needs a custom kernel with `CONFIG_TEE`, `CONFIG_OPTEE` and
  `CONFIG_TCG_FTPM_TEE`; the stock kernel does ship `CONFIG_TCG_TIS_SPI`, which
  is why the `spi-tpm` variant is the one that currently works end to end.

* **UEFI variables are volatile.** Storing them in RPMB through OP-TEE's
  StandaloneMM partition is not working yet, so Secure Boot enrolment does not
  survive a reboot. See `artifacts/rockpi4c/u-boot/configs/rpmb.cfg`.

* **Its secure storage is not secret on this SoC, and cannot be.** OP-TEE
  derives the eMMC RPMB authentication key as `KDF(HUK, eMMC CID)`
  (`tee_rpmb_key_gen()` in `core/tee/tee_rpmb_fs.c`), where the CID is public
  -- Linux exposes it under `/sys/class/mmc_host/*/cid`. The hardware unique
  key that makes the result secret does not exist for RK3399: OP-TEE's
  `plat-rockchip` implements `tee_otp_get_hw_unique_key()` only for RK3588, on
  top of a secure OTP controller (`OTP_S_*` registers, `rockchip_otp.c`) that
  RK3399 does not have. RK3399 has `rockchip,rk3399-efuse` instead, a 128-byte
  window whose cells -- `cpu_id`, the leakage values, wafer info -- are all
  readable from the normal world, and both the Linux and u-boot drivers for it
  are read-only. So OP-TEE falls back to the `CFG_INSECURE` stub, which returns
  a HUK of all zeros; the "This OP-TEE configuration might be insecure!" banner
  on the console is that fallback announcing itself. The RPMB key is therefore
  computable by anyone holding the board, which collapses the replay protection
  the fTPM's NV storage depends on.

  This is why the build sets `CFG_RPMB_TESTKEY=y` deliberately rather than by
  oversight: with no hardware unique key, a "real" derived key would be exactly
  as public, only less honestly labelled. `CFG_RPMB_WRITE_KEY` stays `n`, so
  nothing is programmed -- which also means the fTPM TA will fail with
  `BAD_STATE` in `_plat__NVEnable` on an eMMC whose RPMB key was never written.
  Turning `CFG_RPMB_WRITE_KEY=y` is what makes the line actually run, and it is
  **irreversible**: the eMMC RPMB authentication key is one-time-programmable,
  so the part is then bound to that key forever.

  Lifting this needs an RK3399 implementation of
  `tee_otp_get_hw_unique_key()`, for which the RK3588 platform code is the
  model -- it generates a HUK on first boot and writes it to secure OTP rather
  than reading a factory secret. The open question is whether the RK3399 eFuse
  has a secure-only, programmable region at all; nothing in mainline Linux,
  TF-A or OP-TEE suggests it does, and nobody has written one in the SoC's
  lifetime, Linaro included -- their Trusted Reference Stack shipped on a
  Rock Pi 4 (see the v0.1 docs) but predates all HUK work in `plat-rockchip`,
  which began in 2025 and is RK3588-only. Answering it properly means reading
  the eFuse chapter of the RK3399 TRM.

  None of this affects the `spi-tpm` variant: a discrete TPM keeps its secrets
  inside its own package and derives nothing from the SoC. On RK3588-class
  boards, where the hardware unique key does exist, this same stack would
  deliver the property in full.
