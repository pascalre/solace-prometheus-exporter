package exporter

import (
	"solace_exporter/internal/config"
	"solace_exporter/internal/semp"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// Exporter collects Solace stats from the given URI and exports them using
// the prometheus metrics package.
type Exporter struct {
	config     *config.Config
	dataSource *[]config.DataSource
	logger     log.Logger
	semp       *semp.Semp
}

func NewExporter(logger log.Logger, conf *config.Config, dataSource *[]config.DataSource) *Exporter {
	exp := &Exporter{
		logger:     logger,
		config:     conf,
		dataSource: dataSource,
	}

	httpVisitor, err := exp.httpVisitor()
	if err != nil {
		_ = level.Error(logger).Log("msg", "Failed to create HTTP visitor", "err", err)
	}

	exp.semp = semp.NewSemp(
		logger,
		conf.ScrapeConfig.URI,
		exp.newHTTPClient(),
		httpVisitor,
		conf.LogBrokerToSlowWarnings,
		conf.ScrapeConfig.IsHWBroker,
	)

	return exp
}
