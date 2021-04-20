package uiserver

import (
	"log"
	"net/http"
	"strings"
)

func (srv *uiServer) authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		log.Printf("RequestURI: %s\n", r.RequestURI)

		if strings.HasPrefix(r.RequestURI, "/api/login") {
			next.ServeHTTP(w, r)
			return
		}

		if user, err := srv.getUserFromRequest(r); err == nil && user != "" {
			// We found the token in our map
			log.Printf("Authenticated user %s\n", user)
			// Pass down the request to the next middleware (or final handler)
			next.ServeHTTP(w, r)
		} else {
			// Write an error and stop the handler chain
			log.Printf("session error: %s\n", err)
			http.Error(w, "Forbidden", http.StatusUnauthorized)
		}
	})
}

func (srv *uiServer) getUserFromRequest(r *http.Request) (string, error) {
	session, err := srv.store.Get(r, sessioncookiename)
	if err != nil {
		return "", err
	}
	userObj := session.Values["user"]
	log.Printf("userObj: %s\n", userObj)
	if userObj == nil {
		return "", nil
	} else {
		return userObj.(string), nil
	}
}
