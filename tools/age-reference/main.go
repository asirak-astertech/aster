// Copyright 2026 Defense Unicorns, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command age-reference is a bounded interoperability oracle backed by the
// official Go age implementation. It is test tooling, not a production key
// management or provisioning command.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
)

const (
	maxUnprotectedBytes = 125_877
	maxProtectedBytes   = 1024 * 1024
	maxKeyTextBytes     = 1024
)

var (
	errEmptyInput = errors.New("input is empty")
	errTooLarge   = errors.New("input exceeds its interoperability bound")
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "age reference oracle: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}

	switch args[0] {
	case "generate":
		if len(args) != 3 {
			return usageError()
		}
		return generate(args[1], args[2])
	case "fixture":
		if len(args) != 2 {
			return usageError()
		}
		return fixture(args[1])
	case "encrypt":
		if len(args) != 4 {
			return usageError()
		}
		return encrypt(args[1], args[2], args[3])
	case "decrypt":
		if len(args) != 4 {
			return usageError()
		}
		return decrypt(args[1], args[2], args[3])
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: age-reference generate IDENTITY RECIPIENT | fixture OUTPUT | encrypt RECIPIENT INPUT OUTPUT | decrypt IDENTITY INPUT OUTPUT")
}

func generate(identityPath, recipientPath string) error {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return errors.New("could not generate an X25519 identity")
	}

	if err := writeNewFile(identityPath, 0o600, []byte(identity.String()+"\n")); err != nil {
		return fmt.Errorf("could not write identity: %w", err)
	}
	if err := writeNewFile(recipientPath, 0o644, []byte(identity.Recipient().String()+"\n")); err != nil {
		_ = os.Remove(identityPath)
		return fmt.Errorf("could not write recipient: %w", err)
	}
	return nil
}

func fixture(outputPath string) error {
	plaintext := make([]byte, maxUnprotectedBytes)
	for index := range plaintext {
		plaintext[index] = byte((index*131 + index/251) % 256)
	}
	copy(plaintext, []byte("ASTRPB03age-reference-binary-fixture\x00"))
	return writeNewFile(outputPath, 0o600, plaintext)
}

func encrypt(recipientPath, inputPath, outputPath string) error {
	recipientText, err := readTextFile(recipientPath)
	if err != nil {
		return fmt.Errorf("could not read recipient: %w", err)
	}
	recipient, err := age.ParseX25519Recipient(recipientText)
	if err != nil {
		return errors.New("recipient was rejected")
	}

	input, err := os.Open(inputPath)
	if err != nil {
		return errors.New("could not open plaintext input")
	}
	defer input.Close()

	return withNewOutput(outputPath, 0o600, func(output io.Writer) error {
		boundedOutput := &boundedWriter{writer: output, remaining: maxProtectedBytes}
		ageWriter, err := age.Encrypt(boundedOutput, recipient)
		if err != nil {
			return errors.New("could not initialize encryption")
		}

		copied, copyErr := io.Copy(ageWriter, io.LimitReader(input, maxUnprotectedBytes+1))
		closeErr := ageWriter.Close()
		if copyErr != nil {
			return errors.New("could not read plaintext input")
		}
		if copied == 0 {
			return errEmptyInput
		}
		if copied > maxUnprotectedBytes {
			return errTooLarge
		}
		if closeErr != nil {
			return errors.New("could not finalize encryption")
		}
		return nil
	})
}

func decrypt(identityPath, inputPath, outputPath string) error {
	identityText, err := readTextFile(identityPath)
	if err != nil {
		return fmt.Errorf("could not read identity: %w", err)
	}
	identity, err := age.ParseX25519Identity(identityText)
	if err != nil {
		return errors.New("identity was rejected")
	}

	protected, err := readBoundedFile(inputPath, maxProtectedBytes)
	if err != nil {
		return fmt.Errorf("could not read protected input: %w", err)
	}
	reader, err := age.Decrypt(bytes.NewReader(protected), identity)
	if err != nil {
		return errors.New("protected input was rejected")
	}

	plaintext, err := io.ReadAll(io.LimitReader(reader, maxUnprotectedBytes+1))
	if err != nil {
		clear(plaintext)
		return errors.New("protected input failed authentication")
	}
	defer clear(plaintext)
	if len(plaintext) == 0 {
		return errEmptyInput
	}
	if len(plaintext) > maxUnprotectedBytes {
		return errTooLarge
	}
	return writeNewFile(outputPath, 0o600, plaintext)
}

func readTextFile(path string) (string, error) {
	contents, err := readBoundedFile(path, maxKeyTextBytes)
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(string(contents))
	if text == "" {
		return "", errEmptyInput
	}
	return text, nil
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	input, err := os.Open(path)
	if err != nil {
		return nil, errors.New("input could not be opened")
	}
	defer input.Close()

	contents, err := io.ReadAll(io.LimitReader(input, maximum+1))
	if err != nil {
		return nil, errors.New("input could not be read")
	}
	if int64(len(contents)) > maximum {
		return nil, errTooLarge
	}
	if len(contents) == 0 {
		return nil, errEmptyInput
	}
	return contents, nil
}

func writeNewFile(path string, mode os.FileMode, contents []byte) error {
	return withNewOutput(path, mode, func(output io.Writer) error {
		written, err := output.Write(contents)
		if err == nil && written != len(contents) {
			return io.ErrShortWrite
		}
		return err
	})
}

type boundedWriter struct {
	writer    io.Writer
	remaining int64
}

func (writer *boundedWriter) Write(contents []byte) (int, error) {
	if int64(len(contents)) > writer.remaining {
		return 0, errTooLarge
	}
	written, err := writer.writer.Write(contents)
	writer.remaining -= int64(written)
	return written, err
}

func withNewOutput(path string, mode os.FileMode, write func(io.Writer) error) error {
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return errors.New("output could not be created")
	}

	if err := write(output); err != nil {
		_ = output.Close()
		_ = os.Remove(path)
		return err
	}
	if err := output.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("output could not be closed")
	}
	return nil
}
