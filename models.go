package auth

import (
	"net/http"
)

type versionType = string

type RecieverFunc func(w http.ResponseWriter, r *http.Request)
