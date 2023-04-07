package spdxhelpers

import "github.com/anchore/syft/syft/pkg"

func Summary(p pkg.Package) string {
	if hasMetadata(p) {
		switch metadata := p.Metadata.(type) {
		case pkg.RpmMetadata:
			return metadata.Summary
		}
	}
	return ""
}
