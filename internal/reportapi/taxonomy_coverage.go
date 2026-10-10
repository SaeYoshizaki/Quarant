package reportapi

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type TaxonomyCoverageReport struct {
	GeneratedAt     string                   `json:"generated_at"`
	Version         string                   `json:"version"`
	Source          TaxonomyCoverageSources  `json:"source"`
	Metrics         TaxonomyCoverageMetrics  `json:"metrics"`
	Policy          SecurityTaxonomyPolicy   `json:"policy"`
	BySource        []TaxonomyCoverageSource `json:"by_source,omitempty"`
	ByEngine        []TaxonomyCoverageSource `json:"by_engine,omitempty"`
	ByTaxonomy      []TaxonomyCoverageTerm   `json:"by_taxonomy,omitempty"`
	ByTechnique     []KV                     `json:"by_normalized_technique,omitempty"`
	Limitations     []string                 `json:"limitations,omitempty"`
	Recommendations []string                 `json:"recommendations,omitempty"`
}

type TaxonomyCoverageSources struct {
	SecurityEvents string `json:"security_events,omitempty"`
	Policy         string `json:"policy,omitempty"`
}

type TaxonomyCoverageMetrics struct {
	SecurityEventCount              int     `json:"security_event_count"`
	ClassifiedEventCount            int     `json:"classified_event_count"`
	UnclassifiedEventCount          int     `json:"unclassified_event_count"`
	ClassificationCoverage          float64 `json:"classification_coverage"`
	TaxonomyCount                   int     `json:"taxonomy_count"`
	NormalizedTechniqueCount        int     `json:"normalized_technique_count"`
	SourceCount                     int     `json:"source_count"`
	EngineCount                     int     `json:"engine_count"`
	IDSFallbackOnlyCount            int     `json:"ids_fallback_only_count"`
	IDSFallbackOnlyRate             float64 `json:"ids_fallback_only_rate,omitempty"`
	SingleTaxonomyDominanceRate     float64 `json:"single_taxonomy_dominance_rate,omitempty"`
	SingleTaxonomyDominanceTaxonomy string  `json:"single_taxonomy_dominance_taxonomy,omitempty"`
}

type TaxonomyCoverageSource struct {
	Key                  string `json:"key"`
	SecurityEventCount   int    `json:"security_event_count"`
	ClassifiedEventCount int    `json:"classified_event_count"`
	Taxonomy             []KV   `json:"taxonomy,omitempty"`
	NormalizedTechnique  []KV   `json:"normalized_technique,omitempty"`
}

type TaxonomyCoverageTerm struct {
	Taxonomy    string `json:"taxonomy"`
	EventCount  int    `json:"event_count"`
	SourceCount int    `json:"source_count"`
	EngineCount int    `json:"engine_count"`
	Sources     []KV   `json:"sources,omitempty"`
	Engines     []KV   `json:"engines,omitempty"`
}

func LoadSecurityTaxonomyPolicy(path string) (SecurityTaxonomyPolicy, error) {
	if strings.TrimSpace(path) == "" {
		return SecurityTaxonomyDecisionPolicy(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return SecurityTaxonomyPolicy{}, fmt.Errorf("read taxonomy policy %s: %w", path, err)
	}
	var policy SecurityTaxonomyPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return SecurityTaxonomyPolicy{}, fmt.Errorf("decode taxonomy policy %s: %w", path, err)
	}
	return normalizeSecurityTaxonomyPolicy(policy), nil
}

func LoadTaxonomyCoverageReport(securityEventsPath, policyPath string) (TaxonomyCoverageReport, error) {
	policy, err := LoadSecurityTaxonomyPolicy(policyPath)
	if err != nil {
		return TaxonomyCoverageReport{}, err
	}
	events, err := LoadSecurityEvents(securityEventsPath)
	if err != nil {
		return TaxonomyCoverageReport{}, err
	}
	report := BuildTaxonomyCoverageReport(events, policy)
	report.Source.SecurityEvents = securityEventsPath
	report.Source.Policy = policyPath
	return report, nil
}

func BuildTaxonomyCoverageReport(events []SecurityEvent, policy SecurityTaxonomyPolicy) TaxonomyCoverageReport {
	policy = normalizeSecurityTaxonomyPolicy(policy)
	events = NormalizeSecurityEventsWithPolicy(events, policy)
	report := TaxonomyCoverageReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Version:     "taxonomy-coverage-v1",
		Policy:      policy,
		Limitations: []string{
			"Taxonomy normalization groups evidence for explanation; it does not prove exploitability or compromise.",
			"IDS rule metadata quality affects normalized taxonomy quality.",
		},
		Recommendations: []string{
			"Review events left unclassified or classified only as ids_alert.",
			"Keep custom taxonomy policy JSON with the reproducibility package.",
		},
	}
	taxonomyCounts := map[string]int{}
	techniqueCounts := map[string]int{}
	sourceCounts := map[string]int{}
	engineCounts := map[string]int{}
	sourceStats := map[string]*taxonomyCoverageAccumulator{}
	engineStats := map[string]*taxonomyCoverageAccumulator{}
	termStats := map[string]*taxonomyTermAccumulator{}
	for _, event := range events {
		report.Metrics.SecurityEventCount++
		source := taxonomyCoverageKey(event.Source, "unknown_source")
		engine := taxonomyCoverageKey(firstNonEmpty(event.Engine, event.Sensor), "unknown_engine")
		sourceCounts[source]++
		engineCounts[engine]++
		sourceAcc := ensureTaxonomyCoverageAccumulator(sourceStats, source)
		engineAcc := ensureTaxonomyCoverageAccumulator(engineStats, engine)
		sourceAcc.events++
		engineAcc.events++
		if event.NormalizedTechnique != "" {
			addCount(techniqueCounts, event.NormalizedTechnique)
			addCount(sourceAcc.techniques, event.NormalizedTechnique)
			addCount(engineAcc.techniques, event.NormalizedTechnique)
		}
		classified := len(event.Taxonomy) > 0
		if classified {
			report.Metrics.ClassifiedEventCount++
			sourceAcc.classified++
			engineAcc.classified++
		} else {
			report.Metrics.UnclassifiedEventCount++
		}
		if taxonomyIDSFallbackOnly(event.Taxonomy) {
			report.Metrics.IDSFallbackOnlyCount++
		}
		for _, taxonomy := range event.Taxonomy {
			addCount(taxonomyCounts, taxonomy)
			addCount(sourceAcc.taxonomy, taxonomy)
			addCount(engineAcc.taxonomy, taxonomy)
			termAcc := ensureTaxonomyTermAccumulator(termStats, taxonomy)
			termAcc.events++
			addCount(termAcc.sources, source)
			addCount(termAcc.engines, engine)
		}
	}
	report.Metrics.TaxonomyCount = len(taxonomyCounts)
	report.Metrics.NormalizedTechniqueCount = len(techniqueCounts)
	report.Metrics.SourceCount = len(sourceCounts)
	report.Metrics.EngineCount = len(engineCounts)
	if report.Metrics.SecurityEventCount > 0 {
		report.Metrics.ClassificationCoverage = float64(report.Metrics.ClassifiedEventCount) / float64(report.Metrics.SecurityEventCount)
		report.Metrics.IDSFallbackOnlyRate = float64(report.Metrics.IDSFallbackOnlyCount) / float64(report.Metrics.SecurityEventCount)
	}
	topTaxonomy := topKV(toSortedKV(nonGenericTaxonomyCounts(taxonomyCounts)))
	if topTaxonomy.Count > 0 && report.Metrics.SecurityEventCount > 0 {
		report.Metrics.SingleTaxonomyDominanceTaxonomy = topTaxonomy.Key
		report.Metrics.SingleTaxonomyDominanceRate = float64(topTaxonomy.Count) / float64(report.Metrics.SecurityEventCount)
	}
	report.BySource = taxonomyCoverageAccumulatorRows(sourceStats)
	report.ByEngine = taxonomyCoverageAccumulatorRows(engineStats)
	report.ByTaxonomy = taxonomyCoverageTermRows(termStats)
	report.ByTechnique = toSortedKV(techniqueCounts)
	return report
}

type taxonomyCoverageAccumulator struct {
	events     int
	classified int
	taxonomy   map[string]int
	techniques map[string]int
}

type taxonomyTermAccumulator struct {
	events  int
	sources map[string]int
	engines map[string]int
}

func ensureTaxonomyCoverageAccumulator(items map[string]*taxonomyCoverageAccumulator, key string) *taxonomyCoverageAccumulator {
	if items[key] == nil {
		items[key] = &taxonomyCoverageAccumulator{taxonomy: map[string]int{}, techniques: map[string]int{}}
	}
	return items[key]
}

func ensureTaxonomyTermAccumulator(items map[string]*taxonomyTermAccumulator, key string) *taxonomyTermAccumulator {
	if items[key] == nil {
		items[key] = &taxonomyTermAccumulator{sources: map[string]int{}, engines: map[string]int{}}
	}
	return items[key]
}

func taxonomyCoverageAccumulatorRows(items map[string]*taxonomyCoverageAccumulator) []TaxonomyCoverageSource {
	rows := make([]TaxonomyCoverageSource, 0, len(items))
	for key, item := range items {
		rows = append(rows, TaxonomyCoverageSource{
			Key:                  key,
			SecurityEventCount:   item.events,
			ClassifiedEventCount: item.classified,
			Taxonomy:             toSortedKV(item.taxonomy),
			NormalizedTechnique:  toSortedKV(item.techniques),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return rows
}

func taxonomyCoverageTermRows(items map[string]*taxonomyTermAccumulator) []TaxonomyCoverageTerm {
	rows := make([]TaxonomyCoverageTerm, 0, len(items))
	for key, item := range items {
		rows = append(rows, TaxonomyCoverageTerm{
			Taxonomy:    key,
			EventCount:  item.events,
			SourceCount: len(item.sources),
			EngineCount: len(item.engines),
			Sources:     toSortedKV(item.sources),
			Engines:     toSortedKV(item.engines),
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].EventCount == rows[j].EventCount {
			return rows[i].Taxonomy < rows[j].Taxonomy
		}
		return rows[i].EventCount > rows[j].EventCount
	})
	return rows
}

func taxonomyIDSFallbackOnly(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "attack_like", "ids_alert":
		default:
			return false
		}
	}
	return true
}

func taxonomyCoverageKey(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func topKV(values []KV) KV {
	if len(values) == 0 {
		return KV{}
	}
	return values[0]
}

func nonGenericTaxonomyCounts(values map[string]int) map[string]int {
	out := map[string]int{}
	for key, count := range values {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "attack_like", "ids_alert":
			continue
		default:
			out[key] = count
		}
	}
	return out
}
