package config

import (
	"time"
)

type AuthScheme int

const (
	AuthSchemeNone AuthScheme = iota
	AuthSchemeBasic
	AuthSchemeOAuth
)

type CertType int

const (
	CertTypePEM CertType = iota
	CertTypePKCS12
)

type ExporterAuthConfig struct {
	Password string
	Scheme   AuthScheme
	Username string
}

type SEMPAuthConfig struct {
	Scheme            AuthScheme
	OAuthClientID     string
	OAuthClientScope  string
	OAuthClientSecret string
	OAuthTokenURL     string
	Password          string
	Username          string
}

type TLSConfig struct {
	Certificate string
	CertType    CertType
	Enable      bool
	Pkcs12Pass  string
	PrivateKey  string
}

type ScrapeConfig struct {
	Vpn                     string
	IsHWBroker              bool
	ParallelSempConnections int64
	PrefetchInterval        time.Duration
	URI                     string
	Timeout                 time.Duration
	SslVerify               bool
}

type DataSource struct {
	Name         string
	VpnFilter    string
	ItemFilter   string
	MetricFilter []string
}

type Config struct {
	ExporterAuth            ExporterAuthConfig
	ListenAddr              string
	ScrapeConfig            ScrapeConfig
	SEMPAuth                SEMPAuthConfig
	TLS                     TLSConfig
	LogBrokerToSlowWarnings bool
	DataSources             []DataSource
}
