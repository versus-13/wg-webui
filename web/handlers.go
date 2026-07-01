package web

import (
	"bytes"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/sessions"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"

	"github.com/versus/wg-webui/db"
	"github.com/versus/wg-webui/wireguard"
)

var validName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type Handler struct {
	db            *db.DB
	store         *db.DBStore
	wg            *wireguard.Service
	pages         pageTemplates
	sess          sessions.Store
	log           *slog.Logger
	iface         string
	passwordIsSet atomic.Bool
}

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	return r.RemoteAddr
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	tmpl, ok := h.pages[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	lang := getLang(r)
	cloned, err := tmpl.Clone()
	if err != nil {
		h.log.Error("clone template", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cloned.Funcs(template.FuncMap{
		"t":    func(key string) string { return translate(lang, key) },
		"lang": func() string { return lang },
	})
	var buf bytes.Buffer
	if err := cloned.ExecuteTemplate(&buf, "base", data); err != nil {
		h.log.Error("render template", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// SetLang handles GET /lang/{code} — sets the lang cookie and redirects back.
func (h *Handler) SetLang(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	if !knownLangs[code] {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "lang",
		Value:  code,
		Path:   "/",
		MaxAge: 365 * 24 * 3600,
	})
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// SetupPassword handles GET/POST /setup-password (no old password required).
func (h *Handler) SetupPassword(w http.ResponseWriter, r *http.Request) {
	if h.passwordIsSet.Load() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	_, ok, _ := h.db.GetPasswordHash()
	if ok {
		h.passwordIsSet.Store(true)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	type pageData struct{ Flashes []Flash }

	if r.Method == http.MethodPost {
		pw := r.FormValue("password")
		confirm := r.FormValue("confirm")
		if pw == "" {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.empty_password"))
			http.Redirect(w, r, "/setup-password", http.StatusSeeOther)
			return
		}
		if pw != confirm {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.passwords_match"))
			http.Redirect(w, r, "/setup-password", http.StatusSeeOther)
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
		if err != nil {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.hash_error"))
			http.Redirect(w, r, "/setup-password", http.StatusSeeOther)
			return
		}
		if err := h.db.SetPasswordHash(string(hash)); err != nil {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.save_error", err))
			http.Redirect(w, r, "/setup-password", http.StatusSeeOther)
			return
		}
		h.passwordIsSet.Store(true)
		setFlash(h.sess, w, r, "success", tf(r, "flash.password_set"))
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	h.render(w, r, "setup-password.html", pageData{Flashes: getFlash(h.sess, w, r)})
}

// Login handles GET and POST /login.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	type pageData struct{ Flashes []Flash }

	if r.Method == http.MethodPost {
		hash, ok, err := h.db.GetPasswordHash()
		if err != nil || !ok {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.no_password"))
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.FormValue("password"))) != nil {
			h.log.Warn("login failed", "ip", realIP(r))
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.wrong_password"))
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		setLoggedIn(h.sess, w, r)
		h.log.Info("login success", "ip", realIP(r))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	h.render(w, r, "login.html", pageData{Flashes: getFlash(h.sess, w, r)})
}

// Logout handles GET /logout.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	clearSession(h.sess, w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Index handles GET /.
func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	peers, err := h.store.List()
	if err != nil {
		http.Error(w, "failed to list peers", http.StatusInternalServerError)
		return
	}

	handshakes, _ := h.wg.Handshakes()
	nextIP, _ := h.wg.NextIP()

	type pageData struct {
		Peers      []*wireguard.Peer
		Handshakes map[string]string
		Iface      string
		NextIP     string
		Flashes    []Flash
	}
	h.render(w, r, "index.html", pageData{
		Peers:      peers,
		Handshakes: handshakes,
		Iface:      h.iface,
		NextIP:     nextIP,
		Flashes:    getFlash(h.sess, w, r),
	})
}

// AddPeer handles POST /peer/add.
func (h *Handler) AddPeer(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	ip := r.FormValue("ip")

	if !validName.MatchString(name) {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.invalid_name"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	existing, _ := h.store.Get(name)
	if existing != nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.peer_exists", name))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if ip == "" {
		var err error
		ip, err = h.wg.NextIP()
		if err != nil {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.no_free_ip"))
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	priv, pub, psk, err := h.wg.GenerateKeys()
	if err != nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.keygen", err))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	peer := &wireguard.Peer{
		Name:    name,
		IP:      ip,
		PrivKey: priv,
		PubKey:  pub,
		PSK:     psk,
		Enabled: true,
		Created: time.Now().Format("02.01.2006"),
	}

	if err := h.store.Save(peer); err != nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.peer_save", err))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := h.wg.Reload(); err != nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.wg_reload", err))
	}

	h.log.Info("peer added", "name", name, "ip", ip)
	http.Redirect(w, r, "/peer/"+name+"/config", http.StatusSeeOther)
}

// PeerConfig handles GET /peer/{name}/config.
func (h *Handler) PeerConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	peer, _ := h.store.Get(name)
	if peer == nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.peer_not_found"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	confText, err := h.wg.PeerConfigText(peer)
	if err != nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.config_gen", err))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	type pageData struct {
		Peer       *wireguard.Peer
		ConfigText string
		Flashes    []Flash
	}
	h.render(w, r, "config.html", pageData{
		Peer:       peer,
		ConfigText: confText,
		Flashes:    getFlash(h.sess, w, r),
	})
}

// PeerQR handles GET /peer/{name}/qr — serves the peer config as a QR code PNG.
func (h *Handler) PeerQR(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	peer, _ := h.store.Get(name)
	if peer == nil {
		http.NotFound(w, r)
		return
	}

	confText, err := h.wg.PeerConfigText(peer)
	if err != nil {
		h.log.Error("qr: generate config", "peer", name, "err", err)
		http.Error(w, "failed to generate config", http.StatusInternalServerError)
		return
	}

	png, err := qrcode.Encode(confText, qrcode.Low, 256)
	if err != nil {
		h.log.Error("qr: encode", "peer", name, "err", err)
		http.Error(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// DownloadConfig handles GET /peer/{name}/download — generates config on-demand.
func (h *Handler) DownloadConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	peer, _ := h.store.Get(name)
	if peer == nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.peer_not_found"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	confText, err := h.wg.PeerConfigText(peer)
	if err != nil {
		http.Error(w, "failed to generate config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, name))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, confText)
}

// TogglePeer handles POST /peer/{name}/toggle.
func (h *Handler) TogglePeer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	peer, _ := h.store.Get(name)
	if peer == nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.peer_not_found"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	peer.Enabled = !peer.Enabled
	h.store.Save(peer)

	if err := h.wg.Reload(); err != nil {
		h.log.Error("reload after toggle", "name", name, "err", err)
	}

	key := "flash.peer_enabled"
	if !peer.Enabled {
		key = "flash.peer_disabled"
	}
	setFlash(h.sess, w, r, "success", tf(r, key, name))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// DeletePeer handles POST /peer/{name}/delete.
func (h *Handler) DeletePeer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	peer, _ := h.store.Get(name)
	if peer == nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.peer_not_found"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := h.store.Delete(name); err != nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.peer_delete", err))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := h.wg.Reload(); err != nil {
		setFlash(h.sess, w, r, "error", tf(r, "flash.err.wg_not_updated", err))
	} else {
		setFlash(h.sess, w, r, "success", tf(r, "flash.peer_deleted", name))
	}
	h.log.Info("peer deleted", "name", name)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Status handles GET /status.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	out, _ := h.wg.Status()
	type pageData struct {
		Iface   string
		Status  string
		Flashes []Flash
	}
	h.render(w, r, "status.html", pageData{
		Iface:   h.iface,
		Status:  out,
		Flashes: getFlash(h.sess, w, r),
	})
}

// Settings handles GET/POST /settings.
func (h *Handler) Settings(w http.ResponseWriter, r *http.Request) {
	type pageData struct {
		Host    string
		DNS     string
		Flashes []Flash
	}

	if r.Method == http.MethodPost {
		host := r.FormValue("host")
		dns := r.FormValue("dns")
		_ = h.db.SetSetting("host", host)
		_ = h.db.SetSetting("dns", dns)
		setFlash(h.sess, w, r, "success", tf(r, "flash.settings_saved"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	host, _, _ := h.db.GetSetting("host")
	dns, _, _ := h.db.GetSetting("dns")
	h.render(w, r, "settings.html", pageData{
		Host:    host,
		DNS:     dns,
		Flashes: getFlash(h.sess, w, r),
	})
}

// ChangePassword handles GET/POST /change-password.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	type pageData struct{ Flashes []Flash }

	if r.Method == http.MethodPost {
		oldPW := r.FormValue("old_password")
		newPW := r.FormValue("new_password")
		confirm := r.FormValue("confirm")

		hash, ok, err := h.db.GetPasswordHash()
		if err != nil || !ok {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.no_password"))
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(oldPW)) != nil {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.wrong_current_pw"))
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}
		if newPW == "" {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.empty_new_pw"))
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}
		if newPW != confirm {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.passwords_match"))
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}
		newHash, err := bcrypt.GenerateFromPassword([]byte(newPW), 12)
		if err != nil {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.hash_error"))
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}
		if err := h.db.SetPasswordHash(string(newHash)); err != nil {
			setFlash(h.sess, w, r, "error", tf(r, "flash.err.save_error", err))
			http.Redirect(w, r, "/change-password", http.StatusSeeOther)
			return
		}
		setFlash(h.sess, w, r, "success", tf(r, "flash.password_changed"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	h.render(w, r, "change-password.html", pageData{Flashes: getFlash(h.sess, w, r)})
}
