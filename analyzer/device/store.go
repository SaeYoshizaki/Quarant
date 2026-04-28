package device

import (
	"sort"
	"sync"
)

type Store struct {
	mu sync.Mutex

	devices map[string]*DeviceProfile
}

func NewStore() *Store {
	return &Store{
		devices: make(map[string]*DeviceProfile),
	}
}

func NewProfile(ip string) *DeviceProfile {
	return &DeviceProfile{
		IP:                           ip,
		Hosts:                        map[string]bool{},
		UserAgents:                   map[string]bool{},
		Servers:                      map[string]bool{},
		SNIValues:                    map[string]bool{},
		Paths:                        map[string]bool{},
		Ports:                        map[uint16]bool{},
		Protocols:                    map[string]bool{},
		TypeScores:                   map[string]float64{},
		VendorScores:                 map[string]float64{},
		FamilyScores:                 map[string]float64{},
		IdentitySignalObservations:   map[string]ObservationCounter{},
		NotificationObservations:     map[string]ObservationCounter{},
		StorageSignalEndpoints:       map[string]ObservationCounter{},
		StableIdentifierFingerprints: map[string]ObservationCounter{},
		PIIUseDestinations:           map[string]ObservationCounter{},
		SeverityCounts:               map[string]int{},
		OWASPTagCounts:               map[string]int{},
	}
}

func (s *Store) GetOrCreate(ip string) *DeviceProfile {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.devices[ip]
	if !ok {
		d = NewProfile(ip)
		s.devices[ip] = d
	}

	return d
}

func (s *Store) Snapshots() []InventorySnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.devices) == 0 {
		return nil
	}

	keys := make([]string, 0, len(s.devices))
	for ip := range s.devices {
		keys = append(keys, ip)
	}
	sort.Strings(keys)

	out := make([]InventorySnapshot, 0, len(keys))
	for _, ip := range keys {
		out = append(out, s.devices[ip].Snapshot())
	}
	return out
}
