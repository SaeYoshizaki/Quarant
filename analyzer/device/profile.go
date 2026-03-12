package device

type DeviceProfile struct {
	IP string

	Hosts      map[string]bool
	UserAgents map[string]bool
	Servers    map[string]bool
	SNIValues  map[string]bool

	DeviceType string
	Vendor     string
	Model      string

	Confidence float64
	Evidence   []string

	JA3 string

	ObservedServices map[string]bool
	InsecureServices map[string]bool

	AdminSuspected            bool
	ExternalExposureSuspected bool

	RiskReasons map[string]bool
	RiskScore   int
}

func (p *DeviceProfile) AddObservedService(service string) {
	if service == "" {
		return
	}
	if p.ObservedServices == nil {
		p.ObservedServices = make(map[string]bool)
	}
	p.ObservedServices[service] = true
}

func (p *DeviceProfile) AddInsecureService(service string) {
	if service == "" {
		return
	}
	if p.InsecureServices == nil {
		p.InsecureServices = make(map[string]bool)
	}
	p.InsecureServices[service] = true
}

func (p *DeviceProfile) AddRiskReason(reason string) {
	if reason == "" {
		return
	}
	if p.RiskReasons == nil {
		p.RiskReasons = make(map[string]bool)
	}
	p.RiskReasons[reason] = true
}

func (p *DeviceProfile) MarkAdminSuspected() {
	p.AdminSuspected = true
}

func (p *DeviceProfile) MarkExternalExposure() {
	p.ExternalExposureSuspected = true
}

func (p *DeviceProfile) RecalculateRiskScore() {
	score := 0

	if p.InsecureServices["telnet"] {
		score += 40
	}
	if p.InsecureServices["ftp"] {
		score += 30
	}
	if p.InsecureServices["mqtt"] {
		score += 20
	}
	if p.InsecureServices["rtsp"] {
		score += 20
	}
	if p.InsecureServices["coap"] {
		score += 20
	}
	if p.AdminSuspected {
		score += 25
	}
	if p.ExternalExposureSuspected {
		score += 30
	}
	if score > 100 {
		score = 100
	}

	p.RiskScore = score
}