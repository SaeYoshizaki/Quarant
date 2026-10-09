package reportapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type IncidentLabel struct {
	IncidentID string `json:"incident_id,omitempty"`
	Label      string `json:"label"`
	DeviceIP   string `json:"device_ip,omitempty"`
	Note       string `json:"note,omitempty"`
}

type PrecisionEvaluationReport struct {
	GeneratedAt        string                `json:"generated_at"`
	Source             EvaluationSources     `json:"source"`
	Metrics            EvaluationMetrics     `json:"metrics"`
	ByState            []EvaluationBreakdown `json:"by_state"`
	BySeverity         []EvaluationBreakdown `json:"by_severity"`
	BySignal           []EvaluationBreakdown `json:"by_signal"`
	ByLayer            []EvaluationBreakdown `json:"by_layer"`
	UnlabeledIncidents []PrecisionIncident   `json:"unlabeled_incidents,omitempty"`
	FalseNegatives     []IncidentLabel       `json:"false_negatives,omitempty"`
	Recommendations    []string              `json:"recommendations"`
	Limitations        []string              `json:"limitations"`
}

type EvaluationSources struct {
	Incidents string `json:"incidents,omitempty"`
	Labels    string `json:"labels,omitempty"`
}

type EvaluationMetrics struct {
	IncidentCount        int     `json:"incident_count"`
	LabeledIncidentCount int     `json:"labeled_incident_count"`
	UnlabeledCount       int     `json:"unlabeled_count"`
	TruePositiveCount    int     `json:"true_positive_count"`
	FalsePositiveCount   int     `json:"false_positive_count"`
	BenignCount          int     `json:"benign_count"`
	FalseNegativeCount   int     `json:"false_negative_count"`
	UnknownLabelCount    int     `json:"unknown_label_count"`
	Precision            float64 `json:"precision"`
	Recall               float64 `json:"recall,omitempty"`
	FalsePositiveRate    float64 `json:"false_positive_rate"`
	LabelCoverage        float64 `json:"label_coverage"`
}

type EvaluationBreakdown struct {
	Key                string  `json:"key"`
	Total              int     `json:"total"`
	TruePositiveCount  int     `json:"true_positive_count"`
	FalsePositiveCount int     `json:"false_positive_count"`
	BenignCount        int     `json:"benign_count"`
	UnknownLabelCount  int     `json:"unknown_label_count"`
	Precision          float64 `json:"precision"`
}

func LoadPrecisionEvaluationReport(incidentsPath, labelsPath string) (PrecisionEvaluationReport, error) {
	incidents, err := LoadPrecisionIncidents(incidentsPath)
	if err != nil {
		return PrecisionEvaluationReport{}, err
	}
	labels, err := LoadIncidentLabels(labelsPath)
	if err != nil {
		return PrecisionEvaluationReport{}, err
	}
	out := BuildPrecisionEvaluationReport(incidents, labels)
	out.Source = EvaluationSources{Incidents: incidentsPath, Labels: labelsPath}
	return out, nil
}

func LoadPrecisionIncidents(path string) ([]PrecisionIncident, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	var incidents []PrecisionIncident
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var incident PrecisionIncident
		if err := json.Unmarshal([]byte(line), &incident); err != nil {
			continue
		}
		incidents = append(incidents, incident)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return incidents, nil
}

func LoadIncidentLabels(path string) ([]IncidentLabel, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	var labels []IncidentLabel
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var label IncidentLabel
		if err := json.Unmarshal([]byte(line), &label); err != nil {
			continue
		}
		label.Label = normalizeIncidentLabel(label.Label)
		labels = append(labels, label)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return labels, nil
}

func BuildPrecisionEvaluationReport(incidents []PrecisionIncident, labels []IncidentLabel) PrecisionEvaluationReport {
	labelByID := map[string]IncidentLabel{}
	var falseNegatives []IncidentLabel
	for _, label := range labels {
		if label.Label == "false_negative" {
			falseNegatives = append(falseNegatives, label)
			continue
		}
		if strings.TrimSpace(label.IncidentID) != "" {
			labelByID[label.IncidentID] = label
		}
	}

	stateBreakdowns := map[string]*EvaluationBreakdown{}
	severityBreakdowns := map[string]*EvaluationBreakdown{}
	signalBreakdowns := map[string]*EvaluationBreakdown{}
	layerBreakdowns := map[string]*EvaluationBreakdown{}

	report := PrecisionEvaluationReport{
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
		FalseNegatives: falseNegatives,
		Limitations: []string{
			"Evaluation quality depends on human labels and review coverage.",
			"Recall is only meaningful when false_negative labels are recorded.",
			"Benign labels are counted separately from false positives so normal-but-interesting observations can be tuned without being treated as harmful errors.",
		},
	}
	report.Metrics.IncidentCount = len(incidents)
	report.Metrics.FalseNegativeCount = len(falseNegatives)

	for _, incident := range incidents {
		label, labeled := labelByID[incident.ID]
		if !labeled {
			report.Metrics.UnlabeledCount++
			report.UnlabeledIncidents = append(report.UnlabeledIncidents, incident)
			addEvaluationBreakdown(stateBreakdowns, incident.State, "unlabeled")
			addEvaluationBreakdown(severityBreakdowns, incident.Severity, "unlabeled")
			for _, signal := range incident.Signals {
				addEvaluationBreakdown(signalBreakdowns, signal.Key, "unlabeled")
				addEvaluationBreakdown(layerBreakdowns, precisionLayer(signal), "unlabeled")
			}
			continue
		}
		report.Metrics.LabeledIncidentCount++
		addEvaluationMetric(&report.Metrics, label.Label)
		addEvaluationBreakdown(stateBreakdowns, incident.State, label.Label)
		addEvaluationBreakdown(severityBreakdowns, incident.Severity, label.Label)
		for _, signal := range incident.Signals {
			addEvaluationBreakdown(signalBreakdowns, signal.Key, label.Label)
			addEvaluationBreakdown(layerBreakdowns, precisionLayer(signal), label.Label)
		}
	}

	report.Metrics.Precision = ratio(report.Metrics.TruePositiveCount, report.Metrics.TruePositiveCount+report.Metrics.FalsePositiveCount)
	report.Metrics.FalsePositiveRate = ratio(report.Metrics.FalsePositiveCount, report.Metrics.TruePositiveCount+report.Metrics.FalsePositiveCount+report.Metrics.BenignCount)
	report.Metrics.LabelCoverage = ratio(report.Metrics.LabeledIncidentCount, report.Metrics.IncidentCount)
	if report.Metrics.FalseNegativeCount > 0 {
		report.Metrics.Recall = ratio(report.Metrics.TruePositiveCount, report.Metrics.TruePositiveCount+report.Metrics.FalseNegativeCount)
	}
	report.ByState = sortedEvaluationBreakdowns(stateBreakdowns)
	report.BySeverity = sortedEvaluationBreakdowns(severityBreakdowns)
	report.BySignal = sortedEvaluationBreakdowns(signalBreakdowns)
	report.ByLayer = sortedEvaluationBreakdowns(layerBreakdowns)
	report.Recommendations = evaluationRecommendations(report)
	return report
}

func addEvaluationMetric(metrics *EvaluationMetrics, label string) {
	switch normalizeIncidentLabel(label) {
	case "true_positive":
		metrics.TruePositiveCount++
	case "false_positive":
		metrics.FalsePositiveCount++
	case "benign":
		metrics.BenignCount++
	case "":
		metrics.UnknownLabelCount++
	default:
		metrics.UnknownLabelCount++
	}
}

func addEvaluationBreakdown(items map[string]*EvaluationBreakdown, key string, label string) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}
	item := items[key]
	if item == nil {
		item = &EvaluationBreakdown{Key: key}
		items[key] = item
	}
	item.Total++
	switch normalizeIncidentLabel(label) {
	case "true_positive":
		item.TruePositiveCount++
	case "false_positive":
		item.FalsePositiveCount++
	case "benign":
		item.BenignCount++
	case "", "unlabeled":
		item.UnknownLabelCount++
	default:
		item.UnknownLabelCount++
	}
}

func sortedEvaluationBreakdowns(items map[string]*EvaluationBreakdown) []EvaluationBreakdown {
	out := make([]EvaluationBreakdown, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		item.Precision = ratio(item.TruePositiveCount, item.TruePositiveCount+item.FalsePositiveCount)
		out = append(out, *item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FalsePositiveCount == out[j].FalsePositiveCount {
			if out[i].Total == out[j].Total {
				return out[i].Key < out[j].Key
			}
			return out[i].Total > out[j].Total
		}
		return out[i].FalsePositiveCount > out[j].FalsePositiveCount
	})
	return out
}

func evaluationRecommendations(report PrecisionEvaluationReport) []string {
	recs := []string{}
	if report.Metrics.LabelCoverage < 0.8 && report.Metrics.IncidentCount > 0 {
		recs = append(recs, "Increase label coverage before claiming precision; unlabeled incidents still dominate the evaluation.")
	}
	if report.Metrics.FalsePositiveCount > 0 {
		recs = append(recs, "Review high false-positive signals and add suppression or context requirements for those patterns.")
	}
	if report.Metrics.FalseNegativeCount > 0 {
		recs = append(recs, "Inspect false negatives and add observation or correlation rules for missed behavior.")
	}
	if report.Metrics.TruePositiveCount > 0 && report.Metrics.FalsePositiveCount == 0 {
		recs = append(recs, "Current labeled incidents are precise; validate with more days and more device categories.")
	}
	if len(recs) == 0 {
		recs = append(recs, "Start by labeling incidents as true_positive, false_positive, benign, or false_negative.")
	}
	return recs
}

func normalizeIncidentLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	label = strings.ReplaceAll(label, "-", "_")
	switch label {
	case "tp", "true", "true_positive", "confirmed":
		return "true_positive"
	case "fp", "false", "false_positive":
		return "false_positive"
	case "benign", "normal", "expected":
		return "benign"
	case "fn", "missed", "false_negative":
		return "false_negative"
	default:
		return label
	}
}

func ratio(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
