// Copyright 2026 Defense Unicorns, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedReferenceRoundTrip(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	identity := filepath.Join(directory, "identity.txt")
	recipient := filepath.Join(directory, "recipient.txt")
	plaintext := filepath.Join(directory, "plaintext.bin")
	protected := filepath.Join(directory, "protected.age")
	recovered := filepath.Join(directory, "recovered.bin")

	if err := generate(identity, recipient); err != nil {
		t.Fatal(err)
	}
	if err := fixture(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := encrypt(recipient, plaintext, protected); err != nil {
		t.Fatal(err)
	}
	if err := decrypt(identity, protected, recovered); err != nil {
		t.Fatal(err)
	}

	want, err := os.ReadFile(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(recovered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("recovered plaintext does not match the binary fixture")
	}
}

func TestEncryptRejectsOversizedPlaintextWithoutOutput(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	identity := filepath.Join(directory, "identity.txt")
	recipient := filepath.Join(directory, "recipient.txt")
	plaintext := filepath.Join(directory, "oversized.bin")
	protected := filepath.Join(directory, "protected.age")

	if err := generate(identity, recipient); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plaintext, make([]byte, maxUnprotectedBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := encrypt(recipient, plaintext, protected); err == nil {
		t.Fatal("oversized plaintext was accepted")
	}
	if _, err := os.Stat(protected); !os.IsNotExist(err) {
		t.Fatal("failed encryption left a protected output artifact")
	}
}

func TestDecryptRejectsTamperingWithoutOutput(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	identity := filepath.Join(directory, "identity.txt")
	recipient := filepath.Join(directory, "recipient.txt")
	plaintext := filepath.Join(directory, "plaintext.bin")
	protected := filepath.Join(directory, "protected.age")
	tampered := filepath.Join(directory, "tampered.age")
	recovered := filepath.Join(directory, "recovered.bin")

	if err := generate(identity, recipient); err != nil {
		t.Fatal(err)
	}
	if err := fixture(plaintext); err != nil {
		t.Fatal(err)
	}
	if err := encrypt(recipient, plaintext, protected); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(protected)
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-1] ^= 0x80
	if err := os.WriteFile(tampered, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := decrypt(identity, tampered, recovered); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
	if _, err := os.Stat(recovered); !os.IsNotExist(err) {
		t.Fatal("failed decryption left recovered plaintext")
	}
}

func TestBoundedWriterRejectsWriteAtomically(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	writer := boundedWriter{writer: &output, remaining: 3}

	written, err := writer.Write([]byte("four"))
	if !errors.Is(err, errTooLarge) {
		t.Fatalf("expected the size-limit error, got %v", err)
	}
	if written != 0 || output.Len() != 0 {
		t.Fatal("rejected write modified the bounded output")
	}
}
