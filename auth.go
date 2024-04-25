package auth_module

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/kelseyhightower/envconfig"
)

const (
	AuthHeader      = "Authorization"
	UserTokenHeader = "User-Token"
)

var envConf = &EnvConfs{}

var AuthError error
var UserTokenTarget string
var GuestTokenTarget string

func Headers() []string {
	return []string{AuthHeader, UserTokenHeader}
}

func SetUpAuthReader() error {
	AuthError = envconfig.Process("MECUATE", envConf)
	if AuthError != nil {
		return AuthError
	}
	UserTokenTarget = envConf.UserTarget
	GuestTokenTarget = envConf.GuestTarget
	return AuthError
}

func Authorized(r *http.Request) (bool, MecuateClaimsResponse, error) {
	_, err := hasAuthHeader(r)
	if err != nil {
		return failedToken()
	}
	return verificateToken(r)
}

func verificateToken(r *http.Request) (bool, MecuateClaimsResponse, error) {
	UserToken, GuestToken := DecodeUserToken(r.Header.Get(UserTokenHeader))
	if !GuestToken && !UserToken {
		return failedToken()
	}

	TokenString := strings.Split(r.Header.Get(AuthHeader), " ")
	if len(TokenString) < 2 || len(TokenString) > 2 || TokenString[0] != "Bearer" || TokenString[1] == "" {
		return failedToken()
	}

	var cypherKey string
	if GuestToken {
		cypherKey = envConf.GuestSignKey
	}
	if UserToken {
		cypherKey = envConf.AuthSignKey
	}
	token, err := jwt.ParseWithClaims(TokenString[1], &MecuateClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cypherKey), nil
	})
	if err != nil {
		return failedToken(err.Error())
	}

	claims, ok := token.Claims.(*MecuateClaims)
	if ok && token.Valid {
		exp, err := claims.GetExpirationTime()
		expUNIX := exp.Unix()
		if err != nil || expUNIX < time.Now().Unix() {
			return failedToken()
		}
		aud, err := claims.GetAudience()
		if err != nil {
			return failedToken()
		}
		issuer, err := claims.GetIssuer()
		if err != nil || issuer != "mecuate-astrophytum" {
			return failedToken()
		}
		subject, err := claims.GetSubject()
		if err != nil {
			return failedToken()
		}
		issuedAt, err := claims.GetIssuedAt()
		if err != nil || issuedAt.Unix() > time.Now().Unix() {
			return failedToken()
		}
		notBefor, err := claims.GetNotBefore()
		if err != nil || notBefor.Unix() > time.Now().Unix() {
			return failedToken()
		}
		email := claims.Email
		if !Boolean(email) {
			return failedToken()
		}
		realms := claims.Realms
		if !Boolean(realms.Apis) || !Boolean(realms.Media) || !Boolean(realms.Mecuate) {
			return failedToken()
		}
		id := claims.ID
		if !Boolean(id) {
			return failedToken()
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
		return ok, mClaims, nil

	} else {
		return failedToken()
	}
}

func failedToken(e ...interface{}) (bool, MecuateClaimsResponse, error) {
	err := fmt.Errorf("token not valid")
	if val, ok := e[0].(string); val != "" && ok {
		err = fmt.Errorf(val)
	}
	return false, MecuateClaimsResponse{}, err
}

func hasAuthHeader(r *http.Request) (bool, error) {
	authHeader := r.Header.Get(AuthHeader)
	valid := authHeader != ""
	if !valid {
		return valid, fmt.Errorf("no authorization header found")
	}
	return valid, nil
}
