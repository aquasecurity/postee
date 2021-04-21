package uiserver

import (
	"log"
	"net/http"
)

const (
	sessioncookiename = "postee-session-cookie"
)

func (srv *uiServer) login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	session, err := srv.store.Get(r, sessioncookiename)
	if err != nil {
		log.Printf("Get session error %s\n", err)
		session, err = srv.store.New(r, sessioncookiename)
	}
	log.Printf("session user %s\n", session.Values["user"])

	if session.Values["user"] == nil {
		frmusr := r.FormValue("username")
		frmpwd := r.FormValue("password")

		if frmusr == srv.admusr && frmpwd == srv.admpwd {
			session.Values["user"] = frmusr
			err = session.Save(r, w)

			if err != nil {
				log.Printf("Write session error %s\n", err)
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
	}

}

func (srv *uiServer) logout(w http.ResponseWriter, r *http.Request) {
	session, err := srv.store.Get(r, sessioncookiename)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["user"] = ""
	session.Options.MaxAge = -1

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
