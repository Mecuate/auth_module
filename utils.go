package auth_module

import (
	"encoding/json"
)

func Boolean(x string) bool {
	if x == "false" || x == "False" || x == "FALSE" || x == "0" || x == "undefined" || x == "null" || x == "" {
		return false
	}
	return x == "true" || x == "True" || x == "TRUE" || x == "1" || len(x) > 0
}

type RealmPermissions struct {
	R RealmT
}

type RealmPermission struct {
	Apis    bool
	Media   bool
	Mecuate bool
}

func Permissions(R RealmT) *RealmPermissions {
	return &RealmPermissions{R}
}

func (rp *RealmPermissions) Update() RealmPermission {
	return RealmPermission{
		Apis:    evalWrite(rp.R.Apis),
		Media:   evalWrite(rp.R.Media),
		Mecuate: evalWrite(rp.R.Mecuate),
	}
}

func (rp *RealmPermissions) Create() RealmPermission {
	return RealmPermission{
		Apis:    evalCreate(rp.R.Apis),
		Media:   evalCreate(rp.R.Media),
		Mecuate: evalCreate(rp.R.Mecuate),
	}
}

func (rp *RealmPermissions) Delete() RealmPermission {
	return RealmPermission{
		Apis:    evalDelete(rp.R.Apis),
		Media:   evalDelete(rp.R.Media),
		Mecuate: evalDelete(rp.R.Mecuate),
	}
}

func (rp *RealmPermissions) Read() RealmPermission {
	return RealmPermission{
		Apis:    evalRead(rp.R.Apis),
		Media:   evalRead(rp.R.Media),
		Mecuate: evalRead(rp.R.Mecuate),
	}
}

func evalRead(v string) bool {
	res := false
	switch v {
	case "0222":
		res = true
	case "0444":
		res = true
	case "0644":
		res = true
	case "0666":
		res = true
	}
	return res
}

func evalDelete(v string) bool {
	res := false
	switch v {
	case "0222":
		res = false
	case "0444":
		res = false
	case "0644":
		res = false
	case "0666":
		res = true
	}
	return res
}

func evalCreate(v string) bool {
	res := false
	switch v {
	case "0222":
		res = false
	case "0444":
		res = false
	case "0644":
		res = true
	case "0666":
		res = true
	}
	return res
}

func evalWrite(v string) bool {
	res := false
	switch v {
	case "0222":
		res = false
	case "0444":
		res = true
	case "0644":
		res = true
	case "0666":
		res = true
	}
	return res
}

func DecodeUserToken(token string) (bool, bool) {
	if token == "" {
		return false, false
	}

	return token == UserTokenTarget, token == GuestTokenTarget
}

func ParseJSON(data string, model interface{}) error {
	err := json.Unmarshal([]byte(data), &model)
	if err != nil {
		return err
	}
	return nil
}
