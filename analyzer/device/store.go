package device

import "sync"

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
		IP:         ip,
		Hosts:      map[string]bool{},
		UserAgents: map[string]bool{},
		Servers:    map[string]bool{},
		SNIValues:  map[string]bool{},
		Paths:      map[string]bool{},
		Ports:      map[uint16]bool{},
		Protocols:  map[string]bool{},
		TypeScores: map[string]float64{},
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
