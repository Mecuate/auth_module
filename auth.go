package auth_module

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/kelseyhightower/envconfig"
)

func Authorized(w http.ResponseWriter, r *http.Request) bool {
	_, err := hasAuthHeader(r)
	if err != nil {
		noAuthHeader(w, r)
	}

	return verificateToken(w, r)
}

func hasAuthHeader(r *http.Request) (bool, error) {
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

func verificateToken(w http.ResponseWriter, r *http.Request) bool {
	tokenString := strings.Split(r.Header.Get("Authorization"), "Bearer ")[0]
	var envConf = &EnvConfs{}
	var noAuthSecret = envconfig.Process("MECUATE", envConf)
	if noAuthSecret != nil {
		return false
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(envConf.AuthSignKey), nil
	}, jwt.WithLeeway(60*time.Second))

	claims, ok := token.Claims.(*jwt.MapClaims)

	if ok && token.Valid {
		aud, _ := claims.GetAudience()
		issuer, _ := claims.GetIssuer()
		fmt.Printf("%v %v", aud, issuer)
	} else {
		fmt.Println(err)
	}

	return ok && token.Valid
}
