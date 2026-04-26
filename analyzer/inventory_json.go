package analyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"quarant/analyzer/device"
)

type DeviceInventoryReport struct {
	GeneratedAt string                     `json:"generated_at"`
	Devices     []device.InventorySnapshot `json:"devices"`
}

func BuildDeviceInventoryReport(now time.Time, devices []device.InventorySnapshot) DeviceInventoryReport {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	return DeviceInventoryReport{
		GeneratedAt: now.UTC().Format(time.RFC3339),
		Devices:     devices,
	}
}

func MarshalDeviceInventoryReport(now time.Time, devices []device.InventorySnapshot) ([]byte, error) {
	report := BuildDeviceInventoryReport(now, devices)
	return json.MarshalIndent(report, "", "  ")
}

func WriteDeviceInventoryJSON(path string, now time.Time, devices []device.InventorySnapshot) error {
	data, err := MarshalDeviceInventoryReport(now, devices)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, append(data, '\n'), 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

type DeviceInventoryWriter struct {
	path      string
	interval  time.Duration
	snapshots func() []device.InventorySnapshot
	stop      chan struct{}
	done      chan struct{}
}

func NewDeviceInventoryWriter(path string, interval time.Duration, snapshots func() []device.InventorySnapshot) *DeviceInventoryWriter {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &DeviceInventoryWriter{
		path:      path,
		interval:  interval,
		snapshots: snapshots,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
}

func (w *DeviceInventoryWriter) Start() {
	if w == nil || w.path == "" || w.snapshots == nil {
		return
	}

	go func() {
		defer close(w.done)

		_ = WriteDeviceInventoryJSON(w.path, time.Now().UTC(), w.snapshots())

		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				_ = WriteDeviceInventoryJSON(w.path, time.Now().UTC(), w.snapshots())
			case <-w.stop:
				_ = WriteDeviceInventoryJSON(w.path, time.Now().UTC(), w.snapshots())
				return
			}
		}
	}()
}

func (w *DeviceInventoryWriter) Stop() {
	if w == nil {
		return
	}
	select {
	case <-w.done:
		return
	case w.stop <- struct{}{}:
		<-w.done
	}
}
