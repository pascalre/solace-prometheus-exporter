package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/ini.v1"
)

const (
	iniSection = "solace"
)

type Loader struct {
	cfg *ini.File
}

func GetConfig(configFile string) (map[string][]DataSource, *Config, error) {
	loader, err := NewLoader(configFile)
	if err != nil {
		return nil, nil, err
	}

	cfg := loader.loadSettings()

	if err := validate(cfg); err != nil {
		return nil, nil, err
	}

	if configFile == "" {
		return nil, cfg, nil
	}

	endpoints, err := loader.loadEndpoints()
	if err != nil {
		return nil, nil, err
	}

	return endpoints, cfg, nil
}

func NewLoader(configFile string) (*Loader, error) {
	if configFile == "" {
		return &Loader{cfg: nil}, nil
		//		return nil, errors.New("name of config file is empty")
	}

	file, err := ini.Load(configFile)
	if err != nil {
		return nil, fmt.Errorf("unable to load config file %q: %w", configFile, err)
	}

	return &Loader{cfg: file}, nil
}

// todo: either certificate and privateKey or pkcs12File and pkcs12Pass
func (l *Loader) loadSettings() *Config {
	c := defaultConfig()

	apply(l, "LISTEN_ADDR", &c.ListenAddr, parseString)
	apply(l, "ENABLE_TLS", &c.TLS.Enable, parseBool) // todo: add legacy env 'LISTEN_TLS'
	var certType string
	apply(l, "LISTEN_CERT_TYPE", &certType, parseString) // todo: add legacy key 'certType'
	c.TLS.CertType = ParseCertType(certType)
	apply(l, "CERTIFICATE", &c.TLS.Certificate, parseString) // todo: add legacy key 'certificate'
	apply(l, "PRIVATE_KEY", &c.TLS.PrivateKey, parseString)
	apply(l, "PKCS12_PASS", &c.TLS.Pkcs12Pass, parseString)

	// ---- Scrape ----
	apply(l, "SCRAPE_URI", &c.ScrapeConfig.URI, parseString)
	apply(l, "VPN", &c.ScrapeConfig.Vpn, parseString) // todo: add legacy key 'defaultVpn'
	apply(l, "TIMEOUT", &c.ScrapeConfig.Timeout, parseDuration)
	apply(l, "PREFETCH_INTERVAL", &c.ScrapeConfig.PrefetchInterval, parseDuration) // todo: add legacy env 'PREFETCH_INTERVAL'
	apply(l, "PARALLEL_SEMP_CONNECTIONS", &c.ScrapeConfig.ParallelSempConnections, parseInt)
	apply(l, "IS_HW_BROKER", &c.ScrapeConfig.IsHWBroker, parseBool) // todo: add legacy key 'isHWBroker'
	apply(l, "SSL_VERIFY", &c.ScrapeConfig.SslVerify, parseBool)
	apply(l, "LOG_BROKER_TO_SLOW_WARNINGS", &c.LogBrokerToSlowWarnings, parseBool)

	// ---- Exporter Auth ----
	apply(l, "EXPORTER_AUTH_SCHEME", &c.ExporterAuth.Scheme, parseAuthScheme)
	apply(l, "EXPORTER_AUTH_USERNAME", &c.ExporterAuth.Username, parseString)
	apply(l, "EXPORTER_AUTH_PASSWORD", &c.ExporterAuth.Password, parseString)

	// ---- SEMP Auth ----
	apply(l, "AUTH_SCHEME", &c.SEMPAuth.Scheme, parseAuthScheme)
	apply(l, "USERNAME", &c.SEMPAuth.Username, parseString)
	apply(l, "PASSWORD", &c.SEMPAuth.Password, parseString)
	apply(l, "OAUTH_CLIENT_ID", &c.SEMPAuth.OAuthClientID, parseString)         // todo: add legacy key 'oAuthClientID'
	apply(l, "OAUTH_CLIENT_SECRET", &c.SEMPAuth.OAuthClientSecret, parseString) // todo: add legacy key 'oAuthClientSecret'
	apply(l, "OAUTH_TOKEN_URL", &c.SEMPAuth.OAuthTokenURL, parseString)         // todo: add legacy key 'oAuthTokenURL'
	apply(l, "OAUTH_CLIENT_SCOPE", &c.SEMPAuth.OAuthClientScope, parseString)   // todo: add legacy key 'oAuthClientScope'

	return c
}

func defaultConfig() *Config {
	return &Config{
		ListenAddr: ":9628",
		TLS: TLSConfig{
			Enable:   false,
			CertType: CertTypePEM,
		},
		ScrapeConfig: ScrapeConfig{
			URI:                     "http://localhost:8080",
			Vpn:                     "default",
			Timeout:                 5 * time.Second,
			PrefetchInterval:        0 * time.Second,
			ParallelSempConnections: 1,
			IsHWBroker:              false,
			SslVerify:               true,
		},
		ExporterAuth: ExporterAuthConfig{
			Scheme: AuthSchemeNone,
		},
		SEMPAuth: SEMPAuthConfig{
			Scheme: AuthSchemeBasic,
		},
		LogBrokerToSlowWarnings: false,
	}
}

// todo: double check this
func validate(c *Config) error {
	if c.TLS.Enable {
		switch c.TLS.CertType {
		case CertTypePEM:
			if c.TLS.Certificate == "" || c.TLS.PrivateKey == "" {
				return errors.New("TLS enabled but PEM cert or key missing")
			}
		case CertTypePKCS12:
			if c.TLS.Certificate == "" || c.TLS.Pkcs12Pass == "" {
				return errors.New("TLS enabled but PKCS12 file or password missing")
			}
		default:
			return fmt.Errorf("invalid cert type %q", c.TLS.CertType)
		}
	}

	if (c.SEMPAuth.Username == "" || c.SEMPAuth.Password == "") &&
		(c.SEMPAuth.OAuthClientID == "" || c.SEMPAuth.OAuthClientSecret == "" || c.SEMPAuth.OAuthTokenURL == "" || c.SEMPAuth.OAuthClientScope == "") {
		return errors.New("either Basic Auth or OAuth must be configured")
	}

	return nil
}

func keyToLowerCamel(key string) string {
	key = strings.ToLower(key)

	parts := strings.Split(key, "_")
	for i := range parts {
		if len(parts[i]) == 0 {
			continue
		}
		runes := []rune(parts[i])
		if i == 0 {
			// first word lowerCase
			runes[0] = unicode.ToLower(runes[0])
		} else {
			// following words UpperCase
			runes[0] = unicode.ToUpper(runes[0])
		}
		parts[i] = string(runes)
	}

	return strings.Join(parts, "")
}

func apply[T any](l *Loader, env string, target *T, parseFunc func(string) (T, error)) {
	if raw, ok := getEnv(env); ok {
		if val, err := parseFunc(raw); err == nil {
			*target = val
			return
		}
	}
	if l.cfg != nil {
		key := keyToLowerCamel(env)
		if raw := l.cfg.Section(iniSection).Key(key).String(); raw != "" {
			if val, err := parseFunc(raw); err == nil {
				*target = val
				return
			}
		}
	}
}

func getEnv(env string) (string, bool) {
	v := os.Getenv("SOLACE_" + env)
	return v, v != ""
}

func parseString(s string) (string, error) { return s, nil }

func parseBool(s string) (bool, error) {
	return strconv.ParseBool(s)
}

func parseInt(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

func parseAuthScheme(s string) (AuthScheme, error) {
	switch strings.ToLower(s) {
	case "basic":
		return AuthSchemeBasic, nil
	case "oauth":
		return AuthSchemeOAuth, nil
	default:
		return AuthSchemeNone, nil
	}
}

func ParseCertType(s string) CertType {
	switch strings.ToLower(s) {
	case "pkcs12":
		return CertTypePKCS12
	default:
		return CertTypePEM
	}
}

func (l *Loader) loadEndpoints() (map[string][]DataSource, error) {
	endpoints := make(map[string][]DataSource)
	var scrapeTargetRe = regexp.MustCompile(`^(\w+)(\.\d+)?$`)
	for _, section := range l.cfg.Sections() {
		if strings.HasPrefix(section.Name(), "endpoint.") {
			endpointName := strings.TrimPrefix(section.Name(), "endpoint.")

			var dataSource []DataSource
			for _, key := range section.Keys() {
				scrapeTarget := scrapeTargetRe.ReplaceAllString(key.Name(), `$1`)

				parts := strings.Split(key.String(), "|")
				if len(parts) < 2 {
					return nil, fmt.Errorf("one or two | expected at endpoint %q. Found key %q value %q. Expected: VPN wildcard | item wildcard | Optional metric filter for v2 apis", endpointName, key.Name(), key.String())
				}

				var metricFilter []string
				if len(parts) == 3 && len(strings.TrimSpace(parts[2])) > 0 {
					metricFilter = strings.Split(parts[2], ",")
				}

				dataSource = append(dataSource, DataSource{
					Name:         scrapeTarget,
					VpnFilter:    parts[0],
					ItemFilter:   parts[1],
					MetricFilter: metricFilter,
				})
			}

			endpoints[endpointName] = dataSource
		}
	}
	return endpoints, nil
}

func (c *Config) ListenURI() string {
	scheme := "http"
	if c.TLS.Enable {
		scheme = "https"
	}
	return scheme + "://" + c.ListenAddr
}

func (dataSource DataSource) String() string {
	return fmt.Sprintf("%s=%s|%s|%s", dataSource.Name, dataSource.VpnFilter, dataSource.ItemFilter, strings.Join(dataSource.MetricFilter, ","))
}
