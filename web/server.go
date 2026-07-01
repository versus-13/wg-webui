package web

import (
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/versus/wg-webui/db"
	"github.com/versus/wg-webui/wireguard"
)

var templateFuncs = template.FuncMap{
	"countEnabled": func(peers []*wireguard.Peer) int {
		n := 0
		for _, p := range peers {
			if p.Enabled {
				n++
			}
		}
		return n
	},
	// t and lang are overridden at render time with per-request closures;
	// these placeholders exist only so templates parse successfully.
	"t":       func(key string) string { return key },
	"lang":    func() string { return "en" },
	"version": func() string { return Version },
}

type pageTemplates map[string]*template.Template

func parseTemplates() (pageTemplates, error) {
	pages := []string{
		"login.html",
		"index.html",
		"config.html",
		"status.html",
		"settings.html",
		"setup-password.html",
		"change-password.html",
	}
	pt := make(pageTemplates, len(pages))
	for _, page := range pages {
		t, err := template.New("").Funcs(templateFuncs).ParseFS(FS,
			"templates/base.html",
			fmt.Sprintf("templates/%s", page),
		)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		pt[page] = t
	}
	return pt, nil
}

func NewHandler(
	store *db.DBStore,
	database *db.DB,
	wg *wireguard.Service,
	sessionKey string,
	listenAddr string,
	iface string,
	logger *slog.Logger,
) (*Handler, error) {
	pt, err := parseTemplates()
	if err != nil {
		return nil, err
	}

	sessStore := sessions.NewCookieStore([]byte(sessionKey))
	sessStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: true,
	}

	h := &Handler{
		db:    database,
		store: store,
		wg:    wg,
		pages: pt,
		sess:  sessStore,
		log:   logger,
		iface: iface,
	}

	// pre-load password status so first request doesn't need a DB round-trip
	_, ok, _ := database.GetPasswordHash()
	h.passwordIsSet.Store(ok)

	return h, nil
}

func NewServeMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	staticSub, _ := fs.Sub(FS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// language switcher — no auth required
	mux.HandleFunc("GET /lang/{code}", h.SetLang)

	// password setup — no auth required, but accessible only when no password is set
	mux.HandleFunc("GET /setup-password", h.SetupPassword)
	mux.HandleFunc("POST /setup-password", h.SetupPassword)

	// login/logout — go through requirePasswordSet so unset-password state redirects correctly
	mux.HandleFunc("GET /login", h.requirePasswordSet(h.Login))
	mux.HandleFunc("POST /login", h.requirePasswordSet(h.Login))
	mux.HandleFunc("GET /logout", h.requirePasswordSet(h.Logout))

	// protected routes
	protected := func(fn http.HandlerFunc) http.HandlerFunc {
		return h.requirePasswordSet(h.requireLogin(fn))
	}

	mux.HandleFunc("GET /", protected(h.Index))
	mux.HandleFunc("POST /peer/add", protected(h.AddPeer))
	mux.HandleFunc("GET /peer/{name}/config", protected(h.PeerConfig))
	mux.HandleFunc("GET /peer/{name}/qr", protected(h.PeerQR))
	mux.HandleFunc("GET /peer/{name}/download", protected(h.DownloadConfig))
	mux.HandleFunc("POST /peer/{name}/toggle", protected(h.TogglePeer))
	mux.HandleFunc("POST /peer/{name}/delete", protected(h.DeletePeer))
	mux.HandleFunc("GET /status", protected(h.Status))
	mux.HandleFunc("GET /settings", protected(h.Settings))
	mux.HandleFunc("POST /settings", protected(h.Settings))
	mux.HandleFunc("GET /change-password", protected(h.ChangePassword))
	mux.HandleFunc("POST /change-password", protected(h.ChangePassword))

	return mux
}
