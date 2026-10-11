package reportapi

import (
	"fmt"
	"sort"
)

func SourceCoverageFigureSVG(report SourceCoverageReport) string {
	maxValue := researchMaxInt(
		1,
		report.Metrics.OpenWrtOnlyServiceCount,
		report.Metrics.SuricataOnlyServiceCount,
		report.Metrics.ZeekOnlyServiceCount,
		report.Metrics.MultiSourceServiceCount,
		report.Metrics.OpenWrtSuricataOverlap,
		report.Metrics.OpenWrtZeekOverlap,
		report.Metrics.SuricataZeekOverlap,
		report.Metrics.AllSourceOverlap,
	)
	return researchBarFigure("Source Coverage", []ResearchFigureBar{
		{Label: "OpenWrt only", Value: float64(report.Metrics.OpenWrtOnlyServiceCount) / float64(maxValue), Display: fmt.Sprintf("%d", report.Metrics.OpenWrtOnlyServiceCount)},
		{Label: "Suricata only", Value: float64(report.Metrics.SuricataOnlyServiceCount) / float64(maxValue), Display: fmt.Sprintf("%d", report.Metrics.SuricataOnlyServiceCount)},
		{Label: "Zeek only", Value: float64(report.Metrics.ZeekOnlyServiceCount) / float64(maxValue), Display: fmt.Sprintf("%d", report.Metrics.ZeekOnlyServiceCount)},
		{Label: "Multi-source", Value: float64(report.Metrics.MultiSourceServiceCount) / float64(maxValue), Display: fmt.Sprintf("%d", report.Metrics.MultiSourceServiceCount)},
		{Label: "OpenWrt+Suricata", Value: float64(report.Metrics.OpenWrtSuricataOverlap) / float64(maxValue), Display: fmt.Sprintf("%d", report.Metrics.OpenWrtSuricataOverlap)},
		{Label: "OpenWrt+Zeek", Value: float64(report.Metrics.OpenWrtZeekOverlap) / float64(maxValue), Display: fmt.Sprintf("%d", report.Metrics.OpenWrtZeekOverlap)},
		{Label: "Suricata+Zeek", Value: float64(report.Metrics.SuricataZeekOverlap) / float64(maxValue), Display: fmt.Sprintf("%d", report.Metrics.SuricataZeekOverlap)},
		{Label: "All sources", Value: float64(report.Metrics.AllSourceOverlap) / float64(maxValue), Display: fmt.Sprintf("%d", report.Metrics.AllSourceOverlap)},
	})
}

func TaxonomyCoverageFigureSVG(report TaxonomyCoverageReport) string {
	items := append([]TaxonomyCoverageTerm{}, report.ByTaxonomy...)
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].EventCount == items[j].EventCount {
			return items[i].Taxonomy < items[j].Taxonomy
		}
		return items[i].EventCount > items[j].EventCount
	})
	if len(items) > 8 {
		items = items[:8]
	}
	maxValue := 1
	for _, item := range items {
		if item.EventCount > maxValue {
			maxValue = item.EventCount
		}
	}
	bars := make([]ResearchFigureBar, 0, len(items))
	for _, item := range items {
		bars = append(bars, ResearchFigureBar{
			Label:   item.Taxonomy,
			Value:   float64(item.EventCount) / float64(maxValue),
			Display: fmt.Sprintf("%d", item.EventCount),
		})
	}
	if len(bars) == 0 {
		bars = append(bars, ResearchFigureBar{Label: "No taxonomy", Value: 0, Display: "0"})
	}
	return researchBarFigure("Taxonomy Coverage", bars)
}
