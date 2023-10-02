package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

var envPrefix = "MECUATEAUTH"

func Authorized(w http.ResponseWriter, r *http.Request) bool {
	loadFromFile()
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
	tokenString := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlt7InJlYWxtIjoibWVjdWF0ZSIsInJvbGUiOjJ9XSwiZW1haWwiOiJjaGljb21lLmNvYXRsLnRveHRsaUBnbWFpbC5jb20iLCJleHAiOjE2OTUxNjk3NjAsImlhdCI6MTY5MjU3Nzc2MCwiaXNzIjoibWVjdWF0ZS1hc3Ryb3BoeXR1bSIsIm5iZiI6MTY5MjU3Nzc2MCwic3NpZCI6ImEwMTMyNTEzLTI5YWYtNDVkNS04NDZmLWMxMjNiOTk0NjFmYiIsInN1YiI6IjZhMDRiNjY3LTdjNmQtNDMxNi1iNThiLWE0MzcwMGQ1MjE2NSIsInZlcmlmaWVkIjp0cnVlfQ.8mprZv_ozmAwyQ2U03MI9b22W6Fl_SSmWiX2kFiYBdg`
	var envConf = &EnvConfs{}
	var noAuthSecret = envconfig.Process(envPrefix, envConf)
	if noAuthSecret != nil {
		return false
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(envConf.Secret), nil
	}, jwt.WithLeeway(60*time.Second))

	claims, ok := token.Claims.(*jwt.MapClaims)

	if ok && token.Valid {
		aud, _ := claims.GetAudience()
		issuer, _ := claims.GetIssuer()
		fmt.Printf("%v %v", aud, issuer)
	} else {
		fmt.Println(err)
	}

	authString := strings.Split(r.Header.Get("Authorization"), "Bearer ")[1]
	w.Write([]byte(authString))

	return ok
}

func loadFromFile() {
	cfgFileName := localEnvFile
	if cfgFileName != "" {

		err := godotenv.Load(cfgFileName)

		if err != nil {
			fmt.Println("ENV_FILE not found in AUTH package")
		}
	}
}
