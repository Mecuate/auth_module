package auth_module

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/kelseyhightower/envconfig"
)

func Authorized(w http.ResponseWriter, r *http.Request) (bool, MecuateClaimsResponse) {
	_, err := hasAuthHeader(r)
	if err != nil {
		noAuthHeader(w, r)
	}
	return verificateToken(w, r)
}

func verificateToken(w http.ResponseWriter, r *http.Request) (bool, MecuateClaimsResponse) {
	UserToken := r.Header.Get("User-Token") == "user-token"
	TokenString := strings.Split(r.Header.Get("Authorization"), " ")[1]
	var envConf = &EnvConfs{}
	var noAuthSecret = envconfig.Process("MECUATE", envConf)
	if noAuthSecret != nil {
		return failedToken(w, 1)
	}
	var cypherKey = envConf.GuestSignKey

	if UserToken {
		cypherKey = envConf.AuthSignKey
	}

	token, _ := jwt.ParseWithClaims(TokenString, &MecuateClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cypherKey), nil
	})

	claims, ok := token.Claims.(*MecuateClaims)

	if ok && token.Valid {

		exp, err := claims.GetExpirationTime()
		expUNIX := exp.Unix()
		if err != nil || expUNIX < time.Now().Unix() {
			return failedToken(w, 3)
		}
		aud, err := claims.GetAudience()
		if err != nil {
			return failedToken(w, 8)
		}
		issuer, err := claims.GetIssuer()
		if err != nil || issuer != "mecuate-astrophytum" {
			return failedToken(w, 4)
		}
		subject, err := claims.GetSubject()
		if err != nil {
			return failedToken(w, 5)
		}
		issuedAt, err := claims.GetIssuedAt()
		if err != nil || issuedAt.Unix() > time.Now().Unix() {
			return failedToken(w, 6)
		}
		notBefor, err := claims.GetNotBefore()
		if err != nil || notBefor.Unix() > time.Now().Unix() {
			return failedToken(w, 9)
		}
		email := claims.Email
		if !Boolean(email) {
			return failedToken(w, 7)
		}
		realms := claims.Realms
		if !Boolean(realms.Apis) || !Boolean(realms.Media) || !Boolean(realms.Mecuate) {
			return failedToken(w, 11)
		}
		id := claims.ID
		if !Boolean(id) {
			return failedToken(w, 10)
		}
		mClaims := MecuateClaimsResponse{
			Email:    email,
			Realms:   RealmPermissions{realms},
			Audience: aud,
			Valid:    ok,
			Lifetime: fmt.Sprintf("%v", time.Until(exp.Time)),
			Id:       subject,
			Trace:    id,
		}
		return true, mClaims

	} else {
		return failedToken(w, 2)
	}
}

func failedToken(w http.ResponseWriter, num int8) (bool, MecuateClaimsResponse) {
	http.Error(w, errorMessages[num], http.StatusUnauthorized)
	return false, MecuateClaimsResponse{}
}

var errorMessages = map[int8]string{
	1:  "No token.",
	2:  "Invalid token.",
	3:  "Token expired.",
	4:  "Unknown issuer.",
	5:  "Missing user reference.",
	6:  "Missing expedition date.",
	7:  "Missing email.",
	8:  "Missing audience.",
	9:  "Time range failed verification.",
	10: "No ID found.",
	11: "Missing realms.",
	44: "Fly me to the moon\nLet me play among the stars\nLet me see what spring is like\nOn a-Jupiter and Mars\n\nIn other words: hold my hand\nIn other words: baby, kiss me\n\nFill my heart with song\nAnd let me sing for ever more\nYou are all I long for\nAll I worship and adore\n\nIn other words: please, be true\nIn other words: I love you\n\nFill my heart with song\nLet me sing for ever more\nYou are all I long for\nAll I worship and adore\n\nIn other words: please, be true\nIn other words, in other words: I love you",
}

func noAuthHeader(w http.ResponseWriter, r *http.Request) {
	http.Header.Add(w.Header(), "WWW-Authenticate", `JWT realm="Restricted"`)
	http.Header.Add(w.Header(), "User-Token", `SESSION`)
	http.Error(w, "", http.StatusUnauthorized)
}

func hasAuthHeader(r *http.Request) (bool, error) {
	authHeader := r.Header.Get("Authorization")
	valid := authHeader != ""
	if !valid {
		return valid, fmt.Errorf("no authorization header found")
	}
	return valid, nil
}
