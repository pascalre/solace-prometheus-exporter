package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// helper: create temp ini
func writeIni(t *testing.T, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "test.ini")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatalf("failed writing ini: %v", err)
	}
	return f
}

func TestNewLoaderEmptyFileNameFails(t *testing.T) {
	t.Parallel()

	_, err := NewLoader("")
	if err == nil {
		t.Fatal("expected error but got nil")
	}
}

func TestNewLoaderLoadOK(t *testing.T) {
	t.Parallel()

	path := writeIni(t, "[solace]\nlistenAddr = :9000\n")
	l, err := NewLoader(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if l.cfg == nil {
		t.Fatal("expected cfg to be loaded")
	}
}

func TestEnvToLowerCamel(t *testing.T) {
	t.Parallel()

	got := keyToLowerCamel("SCRAPE_URI")
	want := "scrapeUri"
	if got != want {
		t.Fatalf("expected %s got %s", want, got)
	}
}

func TestApplyEnvOverridesIni(t *testing.T) {
	t.Parallel()

	path := writeIni(t, `
[solace]
listenAddr = 0.0.0.0:9628
`)
	os.Setenv("SOLACE_LISTEN_ADDR", "0.0.0.0:9001")
	defer os.Unsetenv("SOLACE_LISTEN_ADDR")

	l, _ := NewLoader(path)
	cfg := l.loadSettings()

	if cfg.ListenAddr != "0.0.0.0:9001" {
		t.Fatalf("expected env value to win, got %s", cfg.ListenAddr)
	}
}

func TestDefaultValuesApplied(t *testing.T) {
	t.Parallel()

	path := writeIni(t, `
[solace]
listenAddr = 0.0.0.0:9628
`)
	l, _ := NewLoader(path)

	cfg := l.loadSettings()

	if cfg.ListenAddr != "0.0.0.0:9628" {
		t.Fatalf("default listen addr not applied")
	}
	if cfg.ScrapeConfig.Timeout != 5*time.Second {
		t.Fatalf("default timeout expected 5s got %v", cfg.ScrapeConfig.Timeout)
	}
}

func TestValidateTLSPEMRequiresCertAndKey(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.TLS.Enable = true
	cfg.TLS.CertType = CertTypePEM
	cfg.TLS.Certificate = ""
	cfg.TLS.PrivateKey = ""

	err := validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for missing pem cert/key")
	}
}

func TestValidateTLSPKCS12RequiresFileAndPass(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.TLS.Enable = true
	cfg.TLS.CertType = CertTypePKCS12
	cfg.TLS.Certificate = ""
	cfg.TLS.Pkcs12Pass = ""

	err := validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for pkcs12 requirements")
	}
}

func TestValidateRequiresEitherBasicOrOAuth(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.SEMPAuth.Username = ""
	cfg.SEMPAuth.Password = ""
	cfg.SEMPAuth.OAuthClientID = ""
	cfg.SEMPAuth.OAuthClientSecret = ""
	cfg.SEMPAuth.OAuthTokenURL = ""
	cfg.SEMPAuth.OAuthClientScope = ""

	err := validate(cfg)
	if err == nil {
		t.Fatal("expected auth validation error")
	}
}

func TestParseAuthScheme(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    string
		expected AuthScheme
	}{
		{input: "basic", expected: AuthSchemeBasic},
		{input: "BASIC", expected: AuthSchemeBasic},
		{input: "oauth", expected: AuthSchemeOAuth},
		{input: "OAUTH", expected: AuthSchemeOAuth},
		{input: "none", expected: AuthSchemeNone},
		{input: "", expected: AuthSchemeNone},
		{input: "invalid", expected: AuthSchemeNone},
	}

	for _, tc := range tests {
		got, err := parseAuthScheme(tc.input)
		if err != nil {
			t.Errorf("parseAuthScheme(%q) returned unexpected error: %v", tc.input, err)
			continue
		}

		if got != tc.expected {
			t.Errorf("parseAuthScheme(%q) = %v, expected %v", tc.input, got, tc.expected)
		}
	}
}

func TestParseCertType(t *testing.T) {
	t.Parallel()

	if ParseCertType("pkcs12") != CertTypePKCS12 {
		t.Fatal("expected pkcs12")
	}
	if ParseCertType("something") != CertTypePEM {
		t.Fatal("expected pem default")
	}
}

func TestLoadEndpointsOK(t *testing.T) {
	t.Parallel()

	path := writeIni(t, `
[endpoint.broker1]
queue1 = vpnA|itemA|metric1,metric2
topic1 = vpnB|itemB|
`)
	ldr, _ := NewLoader(path)

	endpoints, err := ldr.loadEndpoints()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(endpoints) != 1 {
		t.Fatalf("expected one endpoint, got %d", len(endpoints))
	}

	ds := endpoints["broker1"]
	if len(ds) != 2 {
		t.Fatalf("expected 2 datasource entries, got %d", len(ds))
	}

	if ds[0].Name != "queue1" || ds[0].VpnFilter != "vpnA" {
		t.Fatal("unexpected datasource parsing result")
	}
}

func TestLoadEndpointsFailsOnInvalidFormat(t *testing.T) {
	t.Parallel()

	path := writeIni(t, `
[endpoint.broker1]
broken = onlyone
`)
	ldr, _ := NewLoader(path)

	_, err := ldr.loadEndpoints()
	if err == nil {
		t.Fatal("expected error for invalid endpoint entry")
	}
}

func TestListenURI(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	if cfg.ListenURI() != "http://0.0.0.0:9628" {
		t.Fatalf("unexpected listen uri http")
	}

	cfg.TLS.Enable = true
	if cfg.ListenURI() != "https://0.0.0.0:9628" {
		t.Fatalf("unexpected listen uri https")
	}
}

func TestDataSourceString(t *testing.T) {
	t.Parallel()

	ds := DataSource{
		Name:         "queue1",
		VpnFilter:    "vpn",
		ItemFilter:   "item",
		MetricFilter: []string{"a", "b"},
	}
	want := "queue1=vpn|item|a,b"
	if ds.String() != want {
		t.Fatalf("expected %s got %s", want, ds.String())
	}
}
