package auth_module

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type versionType = string

type RecieverFunc func(w http.ResponseWriter, r *http.Request)

type EnvConfs struct {
	AuthSignKey string `required:"true" split_words:"true"`
}

type MecuateClaims struct {
	Email  string `json:"email"`
	Realms RealmT `json:"realms"`
	jwt.RegisteredClaims
}

type RealmT map[string]string

type MecuateClaimsResponse struct {
	Email     string   `json:"email"`
	ExpiresAt int64    `json:"expiresat"`
	IssuedAt  int64    `json:"issuedat"`
	NotBefore int64    `json:"notbefore"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	ID        string   `json:"id"`
	Audience  []string `json:"audience"`
	Realms    RealmT   `json:"realms"`
}
