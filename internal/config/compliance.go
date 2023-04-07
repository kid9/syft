package config

import (
	"github.com/spf13/viper"

	"github.com/anchore/syft/syft/source"
)

type fileCompliance struct {
	Cataloger          catalogerOptions `yaml:"cataloger" json:"cataloger" mapstructure:"cataloger"`
	SkipFilesAboveSize int64            `yaml:"skip-files-above-size" json:"skip-files-above-size" mapstructure:"skip-files-above-size"`
}

func (cfg fileCompliance) loadDefaultValues(v *viper.Viper) {
	v.SetDefault("file-compliance.cataloger.enabled", catalogerEnabledDefault)
	v.SetDefault("file-compliance.cataloger.scope", source.SquashedScope)
}

func (cfg *fileCompliance) parseConfigValues() error {
	return cfg.Cataloger.parseConfigValues()
}
