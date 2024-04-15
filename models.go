package auth_module

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

type versionType = string

type RecieverFunc func(w http.ResponseWriter, r *http.Request)

type EnvConfs struct {
	AuthSignKey  string `required:"true" split_words:"true"`
	GuestSignKey string `required:"true" split_words:"true"`
	UserTarget   string `required:"true" split_words:"true"`
	GuestTarget  string `required:"true" split_words:"true"`
}

type RealmT struct {
	Apis    string `json:"apis"`
	Media   string `json:"media"`
	Mecuate string `json:"mecuate"`
}

type MecuateClaims struct {
	Email  string `json:"email"`
	Realms RealmT `json:"realms"`
	jwt.RegisteredClaims
}

type MecuateClaimsResponse struct {
	Email    string           `json:"email"`
	Realms   RealmPermissions `json:"realms"`
	Audience []string         `json:"audience"`
	Valid    bool             `json:"valid"`
	Lifetime string           `json:"lifetime"`
	Id       string           `json:"user_id"`
	Trace    string           `json:"trace_id"`
}

type OpenFILE struct {
	Filename  string
	DataModel interface{}
}
