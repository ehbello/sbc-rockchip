// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

// UEFI Secure Boot keys for the firmware.
//
// CONFIG_EFI_SECURE_BOOT makes u-boot able to check the signature of what it
// boots, and it enforces nothing until the platform leaves setup mode, which
// takes a platform key. A key enrolled at runtime does not get it there:
// efi_var_restore() drops the secure boot variables when it reads the variable
// store back from the EFI system partition, deliberately, because a platform key
// kept in a file on a FAT filesystem would be one anybody with a card reader
// could replace.
//
//	/*
//	 * Secure boot related and volatile variables shall only be restored
//	 * from U-Boot's preseed.
//	 */
//
// The preseed is a variable store compiled into the image, and the u-boot package
// builds an empty one to reserve the space (see its configs/efi.cfg). This fills
// it in with the keys the image build was given, which is the only place they can
// come from: a firmware published once is used by everybody, so it cannot know
// them, while the image build is already handed the material it signs the boot
// loader and the UKI with.
//
// Filling it in means rewriting u-boot proper, which is a payload of the FIT the
// SPL verifies, so the FIT has to be signed afterwards -- fitsign.go does that,
// and mkimage recomputes the payload hashes as it goes.

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"time"
)

const (
	// secureBootDir is where the imager is handed its secure boot material, and
	// the file names below are what it calls the pieces. They mirror
	// defaultSecureBootPrefix in pkg/imager/profile/input.go and the "well known
	// name" constants in pkg/machinery/constants, so anything that hands the
	// imager keys the documented way puts them where this looks.
	//
	// Spelled out rather than imported: pkg/machinery/constants pulls in
	// containerd's go-cni and siderolabs/crypto, neither of which belongs in a
	// boot loader installer, and four file names do not justify them.
	secureBootDir = "/secureboot"

	// platformKeyAsset and the two after it are the enrolment files, the same
	// names the imager writes to the EFI system partition.
	platformKeyAsset      = "PK.auth"
	keyExchangeKeyAsset   = "KEK.auth"
	signatureKeyAsset     = "db.auth"
	forbiddenSignatureKey = "dbx.auth"

	// secureBootSigningCertAsset is the certificate the image build signs the
	// boot loader and the UKI with.
	secureBootSigningCertAsset = "uki-signing-cert.pem"

	// efiVarFileMagic identifies the variable store; it is the ASCII "UbEfiVa"
	// followed by a format version. See struct efi_var_file in u-boot's
	// include/efi_variable.h.
	efiVarFileMagic = 0x0161566966456255

	// efiVarFileHeaderSize is sizeof(struct efi_var_file): the reserved field,
	// the magic, the length including this header, and a CRC32 over the rest.
	efiVarFileHeaderSize = 24

	// efiVarAttributes are the attributes u-boot itself stores an enrolled key
	// with: NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS |
	// TIME_BASED_AUTHENTICATED_WRITE_ACCESS.
	efiVarAttributes = 0x01 | 0x02 | 0x04 | 0x20

	// winCertTypeEFIGUID is WIN_CERT_TYPE_EFI_GUID, the only certificate type an
	// EFI_VARIABLE_AUTHENTICATION_2 descriptor uses.
	winCertTypeEFIGUID = 0x0EF1
)

// UEFI GUIDs, in the mixed-endian encoding the firmware stores them in: the
// first three fields little-endian, the last two as written.
var (
	guidGlobalVariable = [16]byte{
		0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,
		0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
	} // 8be4df61-93ca-11d2-aa0d-00e098032b8c
	guidImageSecurityDatabase = [16]byte{
		0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45,
		0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f,
	} // d719b2cb-3d3a-4596-a3bc-dad00e67656f
	guidCertX509 = [16]byte{
		0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
		0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
	} // a5c059a1-94e4-4aa7-87b5-ab155c2bf072
	guidCertTypePKCS7 = [16]byte{
		0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49,
		0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7,
	} // 4aafd29d-68df-49ee-8aa9-347d375665a7
)

// efiVariable is one entry of the store.
type efiVariable struct {
	name string
	guid [16]byte
	// stamp is the authentication time, in seconds since the epoch. It is only
	// ever compared against a later write, and the preseed forbids those, so it
	// is carried along rather than relied on.
	stamp uint64
	value []byte
}

// secureBootVariables reads the secure boot material the image build was given
// and returns the variables to seed the firmware with, or nothing at all if it
// was given none.
//
// The .auth files come first because they are what the image build enrols on the
// EFI system partition, so trusting them keeps the firmware and the boot medium
// saying the same thing. Failing that, the signing certificate is what the
// imager itself derives them from, and for a Talos image it is what signs the
// boot loader and the UKI, so it is the certificate the firmware has to trust.
func secureBootVariables(dir string) ([]efiVariable, error) {
	platformKey := filepath.Join(dir, platformKeyAsset)

	if _, err := os.Stat(platformKey); err == nil {
		return authFileVariables(dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to look for %s: %w", platformKey, err)
	}

	certificate := filepath.Join(dir, secureBootSigningCertAsset)

	pemBytes, err := os.ReadFile(certificate)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s does not hold a PEM certificate", certificate)
	}

	list := signatureList(block.Bytes)

	// One certificate, trusted as the platform key, as the key that may change
	// the database, and as the database itself. That is what the imager does with
	// this certificate when it generates the files above, and enrolling anything
	// less would leave the firmware unable to verify what this image build signs.
	return []efiVariable{
		{name: "db", guid: guidImageSecurityDatabase, value: list},
		{name: "KEK", guid: guidGlobalVariable, value: list},
		{name: "PK", guid: guidGlobalVariable, value: list},
	}, nil
}

// authFileVariables reads the enrolment files, which are the signature lists the
// variables hold behind a descriptor authenticating the write.
func authFileVariables(dir string) ([]efiVariable, error) {
	// The order is the order they are seeded in, and PK goes last: it is what
	// ends setup mode, so the keys it authorises are in place before it lands.
	wanted := []struct {
		name  string
		asset string
		guid  [16]byte
	}{
		{"db", signatureKeyAsset, guidImageSecurityDatabase},
		{"dbx", forbiddenSignatureKey, guidImageSecurityDatabase},
		{"KEK", keyExchangeKeyAsset, guidGlobalVariable},
		{"PK", platformKeyAsset, guidGlobalVariable},
	}

	var variables []efiVariable

	for _, want := range wanted {
		path := filepath.Join(dir, want.asset)

		contents, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			// Only a dbx is genuinely optional; without a db there is nothing to
			// verify against, and without a KEK and a PK nothing is enforced.
			if want.name == "dbx" {
				continue
			}

			return nil, fmt.Errorf("%s is missing next to %s", path, platformKeyAsset)
		} else if err != nil {
			return nil, err
		}

		stamp, value, err := splitAuthenticatedVariable(contents)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}

		variables = append(variables, efiVariable{
			name: want.name, guid: want.guid, stamp: stamp, value: value,
		})
	}

	return variables, nil
}

// splitAuthenticatedVariable takes an EFI_VARIABLE_AUTHENTICATION_2 payload
// apart into the timestamp and the value.
//
// The descriptor authenticates a write and is not part of the value: u-boot
// stores the bytes after it, with the timestamp beside them in the entry. The
// preseed never checks the descriptor, so this only has to locate it.
func splitAuthenticatedVariable(contents []byte) (uint64, []byte, error) {
	// EFI_TIME, then a WIN_CERTIFICATE_UEFI_GUID whose dwLength covers itself.
	const timeSize = 16

	if len(contents) < timeSize+8+16 {
		return 0, nil, errors.New("too short to hold an authentication descriptor")
	}

	year := binary.LittleEndian.Uint16(contents[0:])
	month, day := contents[2], contents[3]
	hour, minute, second := contents[4], contents[5], contents[6]

	length := binary.LittleEndian.Uint32(contents[timeSize:])
	certType := binary.LittleEndian.Uint16(contents[timeSize+6:])

	if certType != winCertTypeEFIGUID {
		return 0, nil, fmt.Errorf("wCertificateType is %#x, not WIN_CERT_TYPE_EFI_GUID", certType)
	}

	if !bytes.Equal(contents[timeSize+8:timeSize+8+16], guidCertTypePKCS7[:]) {
		return 0, nil, errors.New("the descriptor is not a PKCS#7 one")
	}

	end := uint64(timeSize) + uint64(length)
	if end > uint64(len(contents)) {
		return 0, nil, fmt.Errorf("dwLength %d runs past the file", length)
	}

	var stamp uint64
	if year != 0 {
		stamp = uint64(time.Date(int(year), time.Month(month), int(day),
			int(hour), int(minute), int(second), 0, time.UTC).Unix())
	}

	return stamp, contents[end:], nil
}

// signatureList wraps one DER certificate in an EFI_SIGNATURE_LIST, which is
// what a secure boot variable holds.
func signatureList(der []byte) []byte {
	// EFI_SIGNATURE_DATA is an owner GUID followed by the certificate. The owner
	// is informational -- nothing in the verification path reads it -- so it is
	// left empty rather than invented.
	const ownerSize = 16

	signatureSize := ownerSize + len(der)
	listSize := 16 + 12 + signatureSize

	out := make([]byte, 0, listSize)
	out = append(out, guidCertX509[:]...)
	out = binary.LittleEndian.AppendUint32(out, uint32(listSize))
	out = binary.LittleEndian.AppendUint32(out, 0) // no signature list header
	out = binary.LittleEndian.AppendUint32(out, uint32(signatureSize))
	out = append(out, make([]byte, ownerSize)...)

	return append(out, der...)
}

// variableStore lays the variables out as struct efi_var_file.
//
// Mind the per-entry length: the doc comment above efi_var_entry calls it
// "length of enty, multiple of 8" and the code disagrees, which is what runs.
// efi_var_mem_ins() sets it to the size of the value alone,
// efi_get_variable_mem() hands it straight back as *data_size, and the next
// entry starts at ALIGN((uintptr_t)data + var->length, 8). Writing the size of
// the whole entry there appends the padding between entries to the value, which
// turns a signature list into one the firmware cannot parse, with no error
// anywhere to say so.
func variableStore(variables []efiVariable) []byte {
	var body []byte

	for _, variable := range variables {
		entry := make([]byte, 0, 32+2*len(variable.name)+2+len(variable.value))
		entry = binary.LittleEndian.AppendUint32(entry, uint32(len(variable.value)))
		entry = binary.LittleEndian.AppendUint32(entry, efiVarAttributes)
		entry = binary.LittleEndian.AppendUint64(entry, variable.stamp)
		entry = append(entry, variable.guid[:]...)

		for _, character := range variable.name {
			entry = binary.LittleEndian.AppendUint16(entry, uint16(character))
		}

		entry = binary.LittleEndian.AppendUint16(entry, 0) // the name is NUL terminated
		entry = append(entry, variable.value...)

		body = append(body, entry...)
		body = append(body, make([]byte, (-len(entry))&7)...) // entries are 8-byte aligned
	}

	store := make([]byte, 0, efiVarFileHeaderSize+len(body))
	store = binary.LittleEndian.AppendUint64(store, 0) // reserved, has to be zero
	store = binary.LittleEndian.AppendUint64(store, efiVarFileMagic)
	store = binary.LittleEndian.AppendUint32(store, uint32(efiVarFileHeaderSize+len(body)))
	store = binary.LittleEndian.AppendUint32(store, crc32.ChecksumIEEE(body))

	return append(store, body...)
}

// reservedVariableStore is the placeholder the u-boot package builds to reserve
// the space: an empty store, then slack, zeroed throughout.
//
// The size is a contract with that package, not something measured here. It could
// be measured -- the slack is zeroed and the store says how much of it is in use
// -- but u-boot's read-only data does not end where the slack does, so a run of
// zeros is not a boundary, and guessing one too long would write over whatever
// follows. Expecting an exact placeholder means the two sides either agree or the
// build fails saying so.
func reservedVariableStore() []byte {
	// Keep in step with artifacts/rockpi4c/u-boot/pkg.yaml.
	const reserved = 16 * 1024

	return append(variableStore(nil), make([]byte, reserved-efiVarFileHeaderSize)...)
}

// enrolSecureBootKeys writes a variable store holding the keys into the space the
// firmware reserves for one, somewhere inside the FIT it is a payload of.
//
// The space is found by its contents rather than by walking the FIT: the
// placeholder is an exact sequence of bytes that cannot occur by accident, and
// looking for it needs no assumption about where a payload starts or how long it
// is -- which is worth avoiding, since the published FIT's own u-boot hash does
// not agree with the payload bounds its properties describe. It is written in
// place, so nothing moves and only the hashes have to be redone.
func enrolSecureBootKeys(fit []byte, variables []efiVariable) error {
	placeholder := reservedVariableStore()

	offset := bytes.Index(fit, placeholder)
	if offset < 0 {
		return errors.New("the firmware reserves no space for a UEFI variable store: it was " +
			"built without CONFIG_EFI_VARIABLES_PRESEED, reserves a different amount, or " +
			"already has keys in it")
	}

	if again := bytes.Index(fit[offset+1:], placeholder); again >= 0 {
		return fmt.Errorf("the firmware reserves space for a UEFI variable store twice, at %d and %d",
			offset, offset+1+again)
	}

	store := variableStore(variables)
	if len(store) > len(placeholder) {
		return fmt.Errorf("the keys need %d bytes and the firmware reserves %d",
			len(store), len(placeholder))
	}

	copy(fit[offset:], store)

	return nil
}
