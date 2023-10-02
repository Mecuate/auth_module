package auth

import (
	"fmt"
	"net/http"
)

func VerifyRequest(w http.ResponseWriter, r *http.Request) {
	_, err := HasAuthHeader(r)
	if err != nil {
		noAuthHeader(w, r)
	}

	fmt.Println("VerifyRequest.", err)

}

func HasAuthHeader(r *http.Request) (bool, error) {
	authHeader := r.Header.Get("Authorization")
	valid := authHeader != ""
	if !valid {
		return valid, fmt.Errorf("no authorization header found")
	}
	return valid, nil
}

func noAuthHeader(w http.ResponseWriter, r *http.Request) {
	http.Header.Add(w.Header(), "WWW-Authenticate", `JWT realm="Restricted"`)
	http.Header.Add(w.Header(), "Access-Control-Astrophytum-Credentials", `SESSION`)
	http.Error(w, "", http.StatusUnauthorized)
}
