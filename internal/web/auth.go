package web

import (
	"net/http"
	"solace_exporter/internal/config"
)

func WrapWithAuth(handler http.Handler, authConf config.ExporterAuthConfig) http.Handler {
	if (authConf.Scheme == config.AuthSchemeBasic) && (len(authConf.Username) > 0) && (len(authConf.Password) > 0) {
		return basicAuth(handler, authConf)
	}
	return handler
}

func basicAuth(h http.Handler, authConf config.ExporterAuthConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != authConf.Username || p != authConf.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized\n"))
			return
		}

		h.ServeHTTP(w, r)
	})
}
