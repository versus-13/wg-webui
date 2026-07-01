package web

import (
	"net/http"
)

func (h *Handler) requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLoggedIn(h.sess, r) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// requirePasswordSet redirects to /setup-password when no password has been configured yet.
func (h *Handler) requirePasswordSet(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.passwordIsSet.Load() {
			next(w, r)
			return
		}
		// double-check in DB in case another process set the password
		_, ok, _ := h.db.GetPasswordHash()
		if ok {
			h.passwordIsSet.Store(true)
			next(w, r)
			return
		}
		http.Redirect(w, r, "/setup-password", http.StatusSeeOther)
	}
}
