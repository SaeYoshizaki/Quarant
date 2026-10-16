// Package knowledge embeds Quarant's curated knowledge base (the JSON files in
// this directory) into every binary, so analysis does not depend on the
// working directory. The Go loader lives in analyzer/knowledge.
package knowledge

import "embed"

//go:embed *.json *.tsv
var Files embed.FS
