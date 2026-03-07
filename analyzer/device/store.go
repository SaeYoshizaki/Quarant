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

func (s *Store) GetOrCreate(ip string) *DeviceProfile {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.devices[ip]
	if !ok {
		d = &DeviceProfile{
			IP:         ip,
			Hosts:      map[string]bool{},
			UserAgents: map[string]bool{},
			Servers:    map[string]bool{},
			SNIValues:  map[string]bool{},
		}
		s.devices[ip] = d
	}

	return d
}
