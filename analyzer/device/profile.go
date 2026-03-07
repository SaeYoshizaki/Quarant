package device

type DeviceProfile struct {
	IP string

	DeviceType string
	Vendor     string
	Model      string

	Confidence float64

	Evidence []string

	Hosts      map[string]bool
	UserAgents map[string]bool
	Servers    map[string]bool

	SNIValues map[string]bool
	JA3       string
}
