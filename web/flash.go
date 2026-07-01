package web

import (
	"encoding/gob"
	"net/http"

	"github.com/gorilla/sessions"
)

type Flash struct {
	Category string
	Text     string
}

func init() {
	gob.Register([]Flash{})
}

func setFlash(store sessions.Store, w http.ResponseWriter, r *http.Request, category, text string) {
	sess, _ := store.Get(r, sessionName)
	flashes := getSessionFlashes(sess)
	flashes = append(flashes, Flash{Category: category, Text: text})
	sess.Values[flashKey] = flashes
	sess.Save(r, w)
}

func getFlash(store sessions.Store, w http.ResponseWriter, r *http.Request) []Flash {
	sess, _ := store.Get(r, sessionName)
	flashes := getSessionFlashes(sess)
	delete(sess.Values, flashKey)
	sess.Save(r, w)
	return flashes
}

func getSessionFlashes(sess *sessions.Session) []Flash {
	v, ok := sess.Values[flashKey]
	if !ok {
		return nil
	}
	f, ok := v.([]Flash)
	if !ok {
		return nil
	}
	return f
}
