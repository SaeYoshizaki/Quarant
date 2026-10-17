package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"quarant/analyzer"
	"quarant/analyzer/device"
)

// loadIdentityState reads --identity-state into the handler; a missing file
// is the first capture and not an error.
func loadIdentityState(path string, handler *analyzer.FlowHandler) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read identity state: %w", err)
	}
	var state device.IdentityState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse identity state %s: %w", path, err)
	}
	handler.ImportIdentityState(state)
	return nil
}

// saveIdentityState writes the state atomically. Host names can name
// people, so the file is readable by the owner only.
func saveIdentityState(path string, handler *analyzer.FlowHandler) error {
	if strings.TrimSpace(path) == "" || handler == nil {
		return nil
	}
	data, err := json.MarshalIndent(handler.ExportIdentityState(), "", " ")
	if err != nil {
		return fmt.Errorf("encode identity state: %w", err)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("write identity state: %w", err)
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write identity state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write identity state: %w", err)
	}
	return nil
}
