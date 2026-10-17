package dataseteval

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"quarant/analyzer/device"
)

// UNSWAttackWindow is one annotated attack from the UNSW IoT attack traces
// (Hamza et al., SOSR 2019): "start,end,features,attack" per victim MAC.
type UNSWAttackWindow struct {
	VictimMAC string
	Start     time.Time
	End       time.Time
	Attack    string // e.g. ArpSpoof100L2D, TcpSynDevice10W2D
}

var attackFamilyRe = regexp.MustCompile(`^([A-Za-z]+?)(\d+)`)

// AttackFamily strips the rate/direction suffix: ArpSpoof100L2D -> ArpSpoof.
func (w UNSWAttackWindow) AttackFamily() string {
	if m := attackFamilyRe.FindStringSubmatch(w.Attack); m != nil {
		return m[1]
	}
	return w.Attack
}

// LoadUNSWAnnotations reads every <mac>.csv in dir.
func LoadUNSWAnnotations(dir string) ([]UNSWAttackWindow, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.csv"))
	if err != nil {
		return nil, err
	}
	var out []UNSWAttackWindow
	for _, path := range files {
		mac := strings.TrimSuffix(filepath.Base(path), ".csv")
		if len(mac) == 12 {
			parts := make([]string, 0, 6)
			for i := 0; i < 12; i += 2 {
				parts = append(parts, mac[i:i+2])
			}
			mac = strings.ToLower(strings.Join(parts, ":"))
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		ws, err := parseUNSWAnnotations(f, mac)
		f.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, ws...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out, nil
}

func parseUNSWAnnotations(r io.Reader, mac string) ([]UNSWAttackWindow, error) {
	var out []UNSWAttackWindow
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		cols := strings.Split(strings.TrimSpace(sc.Text()), ",")
		if len(cols) < 4 {
			continue
		}
		s, err1 := strconv.ParseInt(cols[0], 10, 64)
		e, err2 := strconv.ParseInt(cols[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, UNSWAttackWindow{VictimMAC: mac, Start: time.Unix(s, 0).UTC(), End: time.Unix(e, 0).UTC(), Attack: strings.TrimSpace(cols[3])})
	}
	return out, sc.Err()
}

// attackDetectors maps attack families to Quarant event types.
var attackDetectors = map[string][]string{
	"ArpSpoof": {"IP_MAC_BINDING_CHANGED"},
}

type UNSWAttackFamilyResult struct {
	Family   string `json:"attack_family"`
	Windows  int    `json:"windows_in_capture"`
	Detected int    `json:"detected"`
	Outcome  string `json:"outcome"` // evaluated | no_detector
	// ByRate breaks detection down by attack rate variant (e.g. ArpSpoof1L2D).
	ByRate map[string][2]int `json:"by_variant_detected_of_total,omitempty"`
}

type UNSWAttackReport struct {
	CaptureStart string                   `json:"capture_start"`
	CaptureEnd   string                   `json:"capture_end"`
	Families     []UNSWAttackFamilyResult `json:"families"`
	// EventsOutsideWindows counts detector events with no annotated attack
	// of the matching family nearby (candidate false positives).
	EventsOutsideWindows map[string]int `json:"detector_events_outside_windows"`
	Slack                string         `json:"match_slack"`
}

// EvaluateUNSWAttacks matches detector events to annotated attack windows
// that fall inside the analysed capture. A window counts as detected when a
// matching event occurs within [start-slack, end+slack].
func EvaluateUNSWAttacks(windows []UNSWAttackWindow, inventory []device.InventorySnapshot, events []Event, slack time.Duration) UNSWAttackReport {
	var start, end time.Time
	for _, s := range inventory {
		for _, v := range []string{s.FirstSeen, s.LastSeen} {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				if start.IsZero() || t.Before(start) {
					start = t
				}
				if t.After(end) {
					end = t
				}
			}
		}
	}
	rep := UNSWAttackReport{EventsOutsideWindows: map[string]int{}, Slack: slack.String()}
	if !start.IsZero() {
		rep.CaptureStart, rep.CaptureEnd = start.Format(time.RFC3339), end.Format(time.RFC3339)
	}
	inCapture := func(w UNSWAttackWindow) bool { return !w.Start.Before(start) && !w.End.After(end) }

	families := map[string]*UNSWAttackFamilyResult{}
	for _, w := range windows {
		if start.IsZero() || !inCapture(w) {
			continue
		}
		fam := w.AttackFamily()
		r := families[fam]
		if r == nil {
			r = &UNSWAttackFamilyResult{Family: fam, ByRate: map[string][2]int{}, Outcome: "no_detector"}
			families[fam] = r
		}
		r.Windows++
		counts := r.ByRate[w.Attack]
		counts[1]++
		types := attackDetectors[fam]
		if len(types) > 0 {
			r.Outcome = "evaluated"
			if matchesWindow(events, types, w, slack) {
				r.Detected++
				counts[0]++
			}
		}
		r.ByRate[w.Attack] = counts
	}
	for fam, types := range attackDetectors {
		for _, e := range events {
			if !containsString(types, e.Type) {
				continue
			}
			near := false
			for _, w := range windows {
				if w.AttackFamily() == fam && !e.TS.Before(w.Start.Add(-slack)) && !e.TS.After(w.End.Add(slack)) {
					near = true
					break
				}
			}
			if !near {
				rep.EventsOutsideWindows[e.Type]++
			}
		}
	}
	names := make([]string, 0, len(families))
	for n := range families {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		rep.Families = append(rep.Families, *families[n])
	}
	return rep
}

func matchesWindow(events []Event, types []string, w UNSWAttackWindow, slack time.Duration) bool {
	for _, e := range events {
		if containsString(types, e.Type) && !e.TS.Before(w.Start.Add(-slack)) && !e.TS.After(w.End.Add(slack)) {
			return true
		}
	}
	return false
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
