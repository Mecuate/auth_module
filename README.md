# AUTH module

---

Simple module to validate the request to the backend

-  this module can be integrated to all libraries internal for MecuateAstrophytum with minimal impact
-  this module uses JWT token lib
-  this module is intended to be used whithin GO version 18.1.x

# latest 
### v0.1.2

# install the module

```
go get github.com/Mecuate/auth_module
```

# Description

provides method to validate a users jwt token based on the custom claims, determine user permissions on server service app and returns validation functions to the main app.

# model type
```go
type MecuateClaimsResponse struct {
	Email    string           `json:"email"`
	Realms   RealmPermissions `json:"realms"`
	Audience []string         `json:"audience"`
	Valid    bool             `json:"valid"`
	Lifetime string           `json:"lifetime"`
	Id       string           `json:"user_id"`
	Trace    string           `json:"trace_id"`
}
```

# Example

```go

authorized, claims := auth.Authorized(w, r)

bool_value := claims.Realms.Read().{service_name}
bool_value := claims.Realms.Create().{service_name}
bool_value := claims.Realms.Update().{service_name}
bool_value := claims.Realms.Delete().{service_name}

```