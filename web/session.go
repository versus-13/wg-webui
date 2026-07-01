package web

import (
	"net/http"

	"github.com/gorilla/sessions"
)

const sessionName = "wgui"

const (
	loggedInKey = "logged_in"
	flashKey    = "flash"
)

func isLoggedIn(store sessions.Store, r *http.Request) bool {
	sess, _ := store.Get(r, sessionName)
	v, _ := sess.Values[loggedInKey].(bool)
	return v
}

func setLoggedIn(store sessions.Store, w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, sessionName)
	sess.Values[loggedInKey] = true
	sess.Save(r, w)
}

func clearSession(store sessions.Store, w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, sessionName)
	sess.Options.MaxAge = -1
	sess.Save(r, w)
}
