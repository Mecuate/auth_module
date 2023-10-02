package auth

import (
	"net/http"
)

type versionType = string

type RecieverFunc func(w http.ResponseWriter, r *http.Request)

type EnvConfs struct {
	Secret string `required:"true" split_words:"true"`
}
