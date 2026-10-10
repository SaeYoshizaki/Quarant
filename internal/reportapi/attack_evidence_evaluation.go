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

type AttackEvidenceLabel struct {
	FindingID      string `json:"finding_id,omitempty"`
	Label          string `json:"label"`
	Kind           string `json:"kind,omitempty"`
	SrcIP          string `json:"src_ip,omitempty"`
	TargetDeviceIP string `json:"target_device_ip,omitempty"`
	Note           string `json:"note,omitempty"`
}

type AttackEvidenceEvaluationReport struct {
	GeneratedAt       string                              `json:"generated_at"`
	Source            AttackEvidenceEvaluationSource      `json:"source"`
	Metrics           AttackEvidenceEvaluationMetrics     `json:"metrics"`
	ByKind            []AttackEvidenceEvaluationBreakdown `json:"by_kind"`
	BySeverity        []AttackEvidenceEvaluationBreakdown `json:"by_severity"`
	ByConfidence      []AttackEvidenceEvaluationBreakdown `json:"by_confidence"`
	UnlabeledFindings []AttackEvidenceFinding             `json:"unlabeled_findings,omitempty"`
	Recommendations   []string                            `json:"recommendations"`
	Limitations       []string                            `json:"limitations"`
}

type AttackEvidenceEvaluationSource struct {
	AttackEvidenceReport string `json:"attack_evidence_report,omitempty"`
	Labels               string `json:"labels,omitempty"`
}

type AttackEvidenceEvaluationMetrics struct {
	FindingCount                 int     `json:"finding_count"`
	LabeledFindingCount          int     `json:"labeled_finding_count"`
	UnlabeledCount               int     `json:"unlabeled_count"`
	TrueAttackCount              int     `json:"true_attack_count"`
	LabScannerCount              int     `json:"lab_scanner_count"`
	InternetBackgroundNoiseCount int     `json:"internet_background_noise_count"`
	BenignAdminCount             int     `json:"benign_admin_count"`
	UnknownLabelCount            int     `json:"unknown_label_count"`
	MeaningfulEvidenceCount      int     `json:"meaningful_evidence_count"`
	NoiseOrBenignCount           int     `json:"noise_or_benign_count"`
	MeaningfulEvidenceRate       float64 `json:"meaningful_evidence_rate"`
	NoiseOrBenignRate            float64 `json:"noise_or_benign_rate"`
	LabelCoverage                float64 `json:"label_coverage"`
}

type AttackEvidenceEvaluationBreakdown struct {
	Key                          string  `json:"key"`
	Total                        int     `json:"total"`
	TrueAttackCount              int     `json:"true_attack_count"`
	LabScannerCount              int     `json:"lab_scanner_count"`
	InternetBackgroundNoiseCount int     `json:"internet_background_noise_count"`
	BenignAdminCount             int     `json:"benign_admin_count"`
	UnknownLabelCount            int     `json:"unknown_label_count"`
	UnlabeledCount               int     `json:"unlabeled_count"`
	MeaningfulEvidenceRate       float64 `json:"meaningful_evidence_rate"`
	NoiseOrBenignRate            float64 `json:"noise_or_benign_rate"`
}

func LoadAttackEvidenceEvaluationReport(attackEvidencePath, labelsPath string) (AttackEvidenceEvaluationReport, error) {
	attackEvidence, err := LoadAttackEvidenceReportJSON(attackEvidencePath)
	if err != nil {
		return AttackEvidenceEvaluationReport{}, err
	}
	labels, err := LoadAttackEvidenceLabels(labelsPath)
	if err != nil {
		return AttackEvidenceEvaluationReport{}, err
	}
	report := BuildAttackEvidenceEvaluationReport(attackEvidence, labels)
	report.Source = AttackEvidenceEvaluationSource{AttackEvidenceReport: attackEvidencePath, Labels: labelsPath}
	return report, nil
}

func LoadAttackEvidenceReportJSON(path string) (AttackEvidenceReport, error) {
	if strings.TrimSpace(path) == "" {
		return AttackEvidenceReport{}, fmt.Errorf("attack evidence report path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return AttackEvidenceReport{}, fmt.Errorf("read %s: %w", path, err)
	}
	var report AttackEvidenceReport
	if err := json.Unmarshal(data, &report); err != nil {
		return AttackEvidenceReport{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return report, nil
}

func LoadAttackEvidenceLabels(path string) ([]AttackEvidenceLabel, error) {
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
	labels := []AttackEvidenceLabel{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var label AttackEvidenceLabel
		if err := json.Unmarshal([]byte(line), &label); err != nil {
			continue
		}
		label.Label = normalizeAttackEvidenceLabel(label.Label)
		labels = append(labels, label)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return labels, nil
}

func BuildAttackEvidenceEvaluationReport(attackEvidence AttackEvidenceReport, labels []AttackEvidenceLabel) AttackEvidenceEvaluationReport {
	labelByID := map[string]AttackEvidenceLabel{}
	for _, label := range labels {
		if strings.TrimSpace(label.FindingID) != "" {
			labelByID[label.FindingID] = label
		}
	}
	byKind := map[string]*AttackEvidenceEvaluationBreakdown{}
	bySeverity := map[string]*AttackEvidenceEvaluationBreakdown{}
	byConfidence := map[string]*AttackEvidenceEvaluationBreakdown{}
	report := AttackEvidenceEvaluationReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Limitations: []string{
			"Evaluation quality depends on human labels and reviewer knowledge of the experiment environment.",
			"Internet background noise can be real attack traffic but may not be targeted at the protected IoT deployment.",
			"Lab scanner labels should be reported separately from uncontrolled internet scans.",
		},
	}
	report.Metrics.FindingCount = len(attackEvidence.Findings)
	for _, finding := range attackEvidence.Findings {
		label, labeled := labelByID[finding.ID]
		normalizedLabel := normalizeAttackEvidenceLabel(label.Label)
		if !labeled || normalizedLabel == "" || normalizedLabel == "unlabeled" {
			report.Metrics.UnlabeledCount++
			report.UnlabeledFindings = append(report.UnlabeledFindings, finding)
			addAttackEvidenceBreakdown(byKind, finding.Kind, "unlabeled")
			addAttackEvidenceBreakdown(bySeverity, finding.Severity, "unlabeled")
			addAttackEvidenceBreakdown(byConfidence, finding.Confidence, "unlabeled")
			continue
		}
		report.Metrics.LabeledFindingCount++
		addAttackEvidenceMetric(&report.Metrics, normalizedLabel)
		addAttackEvidenceBreakdown(byKind, finding.Kind, normalizedLabel)
		addAttackEvidenceBreakdown(bySeverity, finding.Severity, normalizedLabel)
		addAttackEvidenceBreakdown(byConfidence, finding.Confidence, normalizedLabel)
	}
	report.Metrics.MeaningfulEvidenceCount = report.Metrics.TrueAttackCount + report.Metrics.LabScannerCount
	report.Metrics.NoiseOrBenignCount = report.Metrics.InternetBackgroundNoiseCount + report.Metrics.BenignAdminCount
	report.Metrics.MeaningfulEvidenceRate = ratio(report.Metrics.MeaningfulEvidenceCount, report.Metrics.LabeledFindingCount)
	report.Metrics.NoiseOrBenignRate = ratio(report.Metrics.NoiseOrBenignCount, report.Metrics.LabeledFindingCount)
	report.Metrics.LabelCoverage = ratio(report.Metrics.LabeledFindingCount, report.Metrics.FindingCount)
	report.ByKind = sortedAttackEvidenceBreakdowns(byKind)
	report.BySeverity = sortedAttackEvidenceBreakdowns(bySeverity)
	report.ByConfidence = sortedAttackEvidenceBreakdowns(byConfidence)
	report.Recommendations = attackEvidenceEvaluationRecommendations(report)
	return report
}

func addAttackEvidenceMetric(metrics *AttackEvidenceEvaluationMetrics, label string) {
	switch normalizeAttackEvidenceLabel(label) {
	case "true_attack":
		metrics.TrueAttackCount++
	case "scanner_lab_generated":
		metrics.LabScannerCount++
	case "internet_background_noise":
		metrics.InternetBackgroundNoiseCount++
	case "benign_admin":
		metrics.BenignAdminCount++
	case "unknown":
		metrics.UnknownLabelCount++
	default:
		metrics.UnknownLabelCount++
	}
}

func addAttackEvidenceBreakdown(items map[string]*AttackEvidenceEvaluationBreakdown, key string, label string) {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unknown"
	}
	item := items[key]
	if item == nil {
		item = &AttackEvidenceEvaluationBreakdown{Key: key}
		items[key] = item
	}
	item.Total++
	switch normalizeAttackEvidenceLabel(label) {
	case "true_attack":
		item.TrueAttackCount++
	case "scanner_lab_generated":
		item.LabScannerCount++
	case "internet_background_noise":
		item.InternetBackgroundNoiseCount++
	case "benign_admin":
		item.BenignAdminCount++
	case "unknown":
		item.UnknownLabelCount++
	case "", "unlabeled":
		item.UnlabeledCount++
	default:
		item.UnknownLabelCount++
	}
}

func sortedAttackEvidenceBreakdowns(items map[string]*AttackEvidenceEvaluationBreakdown) []AttackEvidenceEvaluationBreakdown {
	out := make([]AttackEvidenceEvaluationBreakdown, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		meaningful := item.TrueAttackCount + item.LabScannerCount
		noise := item.InternetBackgroundNoiseCount + item.BenignAdminCount
		labeled := meaningful + noise + item.UnknownLabelCount
		item.MeaningfulEvidenceRate = ratio(meaningful, labeled)
		item.NoiseOrBenignRate = ratio(noise, labeled)
		out = append(out, *item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Total == out[j].Total {
			return out[i].Key < out[j].Key
		}
		return out[i].Total > out[j].Total
	})
	return out
}

func normalizeAttackEvidenceLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	switch label {
	case "true_attack", "attack", "tp", "true_positive":
		return "true_attack"
	case "scanner_lab_generated", "lab_scanner", "lab", "scanner":
		return "scanner_lab_generated"
	case "internet_background_noise", "background_noise", "noise", "internet_noise":
		return "internet_background_noise"
	case "benign_admin", "admin", "benign":
		return "benign_admin"
	case "unknown", "unlabeled", "":
		return label
	default:
		return "unknown"
	}
}

func attackEvidenceEvaluationRecommendations(report AttackEvidenceEvaluationReport) []string {
	recs := []string{}
	if report.Metrics.UnlabeledCount > 0 {
		recs = append(recs, "Label every attack evidence finding before reporting detector precision or noise rate.")
	}
	if report.Metrics.InternetBackgroundNoiseCount > report.Metrics.TrueAttackCount+report.Metrics.LabScannerCount {
		recs = append(recs, "Report internet background noise separately from targeted or lab-generated attack evidence.")
	}
	if report.Metrics.LabelCoverage >= 0.8 {
		recs = append(recs, "Use labeled attack evidence metrics when comparing OpenWrt, Suricata, Zeek, or Snort importers.")
	}
	if len(recs) == 0 {
		recs = append(recs, "Generate attack evidence labels with attack-eval --init-labels and review finding context.")
	}
	return uniqueSortedStrings(recs)
}
