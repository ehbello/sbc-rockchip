// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"hash/crc32"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestVariableStoreLayout reads a store back the way efi_var_restore() does, so
// that the entry length keeps meaning the size of the value. It is documented as
// "length of enty, multiple of 8" and the code disagrees; writing the size of the
// whole entry there instead appends the padding between entries to the value,
// which corrupts a signature list without anything reporting it.
func TestVariableStoreLayout(t *testing.T) {
	// A name of odd length and a value that is not a multiple of eight, so the
	// padding is not zero and gets a chance to be counted by mistake.
	variables := []efiVariable{
		{name: "db", guid: guidImageSecurityDatabase, stamp: 1, value: bytes.Repeat([]byte{0xa5}, 13)},
		{name: "PK", guid: guidGlobalVariable, stamp: 2, value: bytes.Repeat([]byte{0x5a}, 7)},
	}

	store := variableStore(variables)

	if reserved := binary.LittleEndian.Uint64(store); reserved != 0 {
		t.Errorf("reserved is %#x, u-boot requires zero", reserved)
	}

	if magic := binary.LittleEndian.Uint64(store[8:]); magic != efiVarFileMagic {
		t.Errorf("magic is %#x, want %#x", magic, uint64(efiVarFileMagic))
	}

	length := binary.LittleEndian.Uint32(store[16:])
	if int(length) != len(store) {
		t.Errorf("length is %d, the store is %d bytes", length, len(store))
	}

	if got, want := binary.LittleEndian.Uint32(store[20:]), crc32.ChecksumIEEE(store[efiVarFileHeaderSize:length]); got != want {
		t.Errorf("crc32 is %#x, want %#x over the variable area", got, want)
	}

	for offset, i := efiVarFileHeaderSize, 0; offset < int(length); i++ {
		if i >= len(variables) {
			t.Fatalf("the store holds more than the %d variables put in it", len(variables))
		}

		want := variables[i]

		size := binary.LittleEndian.Uint32(store[offset:])
		if int(size) != len(want.value) {
			t.Fatalf("%s: entry length is %d, the value is %d bytes -- it must be the size of the value alone",
				want.name, size, len(want.value))
		}

		if attributes := binary.LittleEndian.Uint32(store[offset+4:]); attributes != efiVarAttributes {
			t.Errorf("%s: attributes are %#x, want %#x", want.name, attributes, efiVarAttributes)
		}

		if stamp := binary.LittleEndian.Uint64(store[offset+8:]); stamp != want.stamp {
			t.Errorf("%s: stamp is %d, want %d", want.name, stamp, want.stamp)
		}

		if !bytes.Equal(store[offset+16:offset+32], want.guid[:]) {
			t.Errorf("%s: guid is %x, want %x", want.name, store[offset+16:offset+32], want.guid)
		}

		// The name is UTF-16 and NUL terminated, and the value follows it.
		end := offset + 32
		for binary.LittleEndian.Uint16(store[end:]) != 0 {
			end += 2
		}

		name := make([]rune, 0, (end-offset-32)/2)
		for at := offset + 32; at < end; at += 2 {
			name = append(name, rune(binary.LittleEndian.Uint16(store[at:])))
		}

		if string(name) != want.name {
			t.Errorf("name is %q, want %q", string(name), want.name)
		}

		value := end + 2
		if got := store[value : value+int(size)]; !bytes.Equal(got, want.value) {
			t.Errorf("%s: value is %x, want %x", want.name, got, want.value)
		}

		// Where efi_var_restore() looks for the next entry.
		offset = (value + int(size) + 7) & ^7
	}
}

// TestVariableStorePutsPlatformKeyLast checks the ordering the firmware needs:
// the platform key is what ends setup mode, so it has to land once the keys it
// authorises are already there.
func TestVariableStorePutsPlatformKeyLast(t *testing.T) {
	dir := t.TempDir()
	writeCertificate(t, filepath.Join(dir, secureBootSigningCertAsset))

	variables, err := secureBootVariables(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(variables) == 0 {
		t.Fatal("no variables from a directory holding a signing certificate")
	}

	if last := variables[len(variables)-1].name; last != "PK" {
		t.Errorf("the last variable is %q, want PK", last)
	}
}

// TestSecureBootVariablesFromCertificate covers the path taken when the image
// build is handed a signing certificate and no enrolment files: all three
// variables have to hold it, or the firmware cannot verify what that build signs.
func TestSecureBootVariablesFromCertificate(t *testing.T) {
	dir := t.TempDir()
	der := writeCertificate(t, filepath.Join(dir, secureBootSigningCertAsset))

	variables, err := secureBootVariables(dir)
	if err != nil {
		t.Fatal(err)
	}

	guids := map[string][16]byte{
		"db":  guidImageSecurityDatabase,
		"KEK": guidGlobalVariable,
		"PK":  guidGlobalVariable,
	}

	if len(variables) != len(guids) {
		t.Fatalf("got %d variables, want %d", len(variables), len(guids))
	}

	for _, variable := range variables {
		want, ok := guids[variable.name]
		if !ok {
			t.Errorf("unexpected variable %q", variable.name)

			continue
		}

		if variable.guid != want {
			t.Errorf("%s: guid is %x, want %x", variable.name, variable.guid, want)
		}

		if !bytes.Contains(variable.value, der) {
			t.Errorf("%s: the signature list does not hold the certificate", variable.name)
		}

		if !bytes.HasPrefix(variable.value, guidCertX509[:]) {
			t.Errorf("%s: the signature list is not an X.509 one", variable.name)
		}
	}
}

// TestSecureBootVariablesWithoutMaterial is the published-firmware case: an image
// build given nothing enrols nothing, rather than failing or inventing a key.
func TestSecureBootVariablesWithoutMaterial(t *testing.T) {
	variables, err := secureBootVariables(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if variables != nil {
		t.Errorf("got %d variables from an empty directory, want none", len(variables))
	}
}

func TestSplitAuthenticatedVariable(t *testing.T) {
	payload := []byte("a signature list")
	stamp := time.Date(2026, time.September, 22, 13, 38, 26, 0, time.UTC)

	for _, test := range []struct {
		name     string
		certType uint16
		guid     [16]byte
		wantErr  bool
	}{
		{name: "pkcs7", certType: winCertTypeEFIGUID, guid: guidCertTypePKCS7},
		{name: "wrong certificate type", certType: 0x0100, guid: guidCertTypePKCS7, wantErr: true},
		{name: "not pkcs7", certType: winCertTypeEFIGUID, guid: guidCertX509, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor := make([]byte, 0, 16)
			descriptor = binary.LittleEndian.AppendUint16(descriptor, uint16(stamp.Year()))
			descriptor = append(descriptor, byte(stamp.Month()), byte(stamp.Day()),
				byte(stamp.Hour()), byte(stamp.Minute()), byte(stamp.Second()), 0)
			descriptor = append(descriptor, make([]byte, 8)...) // nanosecond, timezone, daylight, pad

			certificate := make([]byte, 0)
			certificate = binary.LittleEndian.AppendUint32(certificate, uint32(8+16+4))
			certificate = binary.LittleEndian.AppendUint16(certificate, 0x0200)
			certificate = binary.LittleEndian.AppendUint16(certificate, test.certType)
			certificate = append(certificate, test.guid[:]...)
			certificate = append(certificate, 1, 2, 3, 4) // a stand-in signature

			gotStamp, gotValue, err := splitAuthenticatedVariable(
				append(append(descriptor, certificate...), payload...))

			if test.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if gotStamp != uint64(stamp.Unix()) {
				t.Errorf("stamp is %d, want %d", gotStamp, stamp.Unix())
			}

			if !bytes.Equal(gotValue, payload) {
				t.Errorf("value is %q, want %q", gotValue, payload)
			}
		})
	}
}

// TestEnrolSecureBootKeys writes into the space the u-boot package reserves and
// reads the result back, which is what the firmware does with it.
func TestEnrolSecureBootKeys(t *testing.T) {
	placeholder := reservedVariableStore()

	// The reserved space with firmware either side of it, including a run of
	// zeros, so finding it cannot be a matter of looking for one.
	firmware := func() []byte {
		blob := append([]byte("payload before"), make([]byte, 64)...)
		blob = append(blob, placeholder...)

		return append(blob, append(make([]byte, 64), []byte("payload after")...)...)
	}

	variables := []efiVariable{
		{name: "db", guid: guidImageSecurityDatabase, value: bytes.Repeat([]byte{0xc3}, 300)},
		{name: "PK", guid: guidGlobalVariable, value: bytes.Repeat([]byte{0x3c}, 300)},
	}

	t.Run("in place", func(t *testing.T) {
		blob := firmware()
		before := len(blob)

		if err := enrolSecureBootKeys(blob, variables); err != nil {
			t.Fatal(err)
		}

		if len(blob) != before {
			t.Fatalf("the firmware changed size, %d -> %d", before, len(blob))
		}

		at := bytes.Index(blob, []byte("payload before"))
		if at != 0 {
			t.Errorf("what came before the reserved space moved to %d", at)
		}

		if !bytes.Contains(blob, []byte("payload after")) {
			t.Error("what came after the reserved space was overwritten")
		}

		// The store has to read back as the firmware reads it.
		store := bytes.Index(blob, variableStore(variables))
		if store < 0 {
			t.Fatal("the store is not in the firmware")
		}

		if length := binary.LittleEndian.Uint32(blob[store+16:]); int(length) != len(variableStore(variables)) {
			t.Errorf("length is %d, want %d", length, len(variableStore(variables)))
		}
	})

	t.Run("no reserved space", func(t *testing.T) {
		if err := enrolSecureBootKeys([]byte("firmware without a variable store"), variables); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("reserved twice", func(t *testing.T) {
		if err := enrolSecureBootKeys(append(firmware(), placeholder...), variables); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("too many keys", func(t *testing.T) {
		big := []efiVariable{{name: "db", guid: guidImageSecurityDatabase, value: make([]byte, len(placeholder))}}

		if err := enrolSecureBootKeys(firmware(), big); err == nil {
			t.Error("expected an error")
		}
	})
}

// writeCertificate writes a self-signed certificate in the form the imager is
// handed one, and returns its DER encoding.
func writeCertificate(t *testing.T, path string) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	return der
}
