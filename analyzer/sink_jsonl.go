package analyzer

import (
	"encoding/json"
	"os"
	"sync"
)

type JSONLSink struct {
	mu sync.Mutex
	file *os.File
}

func NewJSONSink(path string) (*JSONLSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &JSONLSink{
		file: f,
	}, nil
}

func (s *JSONLSink) Write(event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	
	_, err = s.file.Write(append(data, '\n'))
	return err
}