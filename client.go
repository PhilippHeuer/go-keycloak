package keycloak

import (
	// Error Handling
	"errors"

	// REST
	"gopkg.in/resty.v1"

	// Encoding
	b64 "encoding/base64"
	"encoding/json"
)

/**
 * The OIDCToken holds all info about the token
 */
type OIDCToken struct {
	AccessToken      string
	ExpiresIn        float64
	RefreshExpiresIn float64
	RefreshToken     string
	TokenType        string
}

/**
 * The keycloak client kind-of class
 */
type KeycloakClient struct {
	Server					 string
}

/**
 * The Keycloak User Structure
 */
type KeycloakUser struct {
	Id               string `json:"id"`
	CreatedTimestamp int64  `json:"createdTimestamp"`
	Username         string `json:"username"`
	Enabled          bool   `json:"enabled"`
	Totp             bool   `json:"totp"`
	EmailVerified    bool   `json:"emailVerified"`
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	Email            string `json:"email"`
	FederationLink   string `json:"federationLink"`
	Attributes       struct {
		LDAPENTRYDN []string `json:"LDAP_ENTRY_DN"`
		LDAPID      []string `json:"LDAP_ID"`
	} `json:"attributes"`
	DisableableCredentialTypes []interface{} `json:"disableableCredentialTypes"`
	RequiredActions            []interface{} `json:"requiredActions"`
	Access                     struct {
		ManageGroupMembership bool `json:"manageGroupMembership"`
		View                  bool `json:"view"`
		MapRoles              bool `json:"mapRoles"`
		Impersonate           bool `json:"impersonate"`
		Manage                bool `json:"manage"`
	} `json:"access"`
}

/**
 * Keycloak User Groups
 */
type KeycloakUserGroup struct {
	Id   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

/**
 * The Keycloak Group Structure
 */
type KeycloakGroup struct {
	Id        string        `json:"id"`
	Name      string        `json:"name"`
	Path      string        `json:"path"`
	SubGroups []interface{} `json:"subGroups"`
}

/**
 * The Keycloak Role Structure
 */
type KeycloakRole struct {
 	Id                 string `json:"id"`
 	Name               string `json:"name"`
 	ScopeParamRequired bool   `json:"scopeParamRequired"`
 	Composite          bool   `json:"composite"`
 	ClientRole         bool   `json:"clientRole"`
 	ContainerID        string `json:"containerId"`
 	Description        string `json:"description,omitempty"`
}

/**
 * Role Mapping for Clients
 */
type ClientRoleMapping struct {
	ID       string `json:"id"`
	Client   string `json:"client"`
	Mappings []ClientRoleMappingRole `json:"mappings"`
}
type ClientRoleMappingRole struct {
	Id                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description,omitempty"`
	ScopeParamRequired bool   `json:"scopeParamRequired"`
	Composite          bool   `json:"composite"`
	ClientRole         bool   `json:"clientRole"`
	ContainerID        string `json:"containerId"`
}

/**
 * Keycloak Client
 */
type KeycloakRealmClient struct {
 	Id                        string        `json:"id"`
 	ClientID                  string        `json:"clientId"`
}

/**
 * Direct Grant Authentication
 * -
 * This method directly gets you the OIDC Token from keycloak to use in your next requests
 */
func (keycloakClient KeycloakClient) DirectGrantAuthentication(clientId string, clientSecret string, realm string, username string, password string) (*OIDCToken, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", getBasicAuthForClient(clientId, clientSecret)).
		SetFormData(map[string]string{
			"grant_type": "password",
			"username":   username,
			"password":   password,
		}).Post(keycloakClient.Server + "/auth/realms/" + realm + "/protocol/openid-connect/token")
	if err != nil {
		return nil, err
	}

	// Here’s the actual decoding, and a check for associated errors.
	var result map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	// Check for Result
	if val, ok := result["access_token"]; ok {
		_ = val
		return &OIDCToken{
			AccessToken:      result["access_token"].(string),
			ExpiresIn:        result["expires_in"].(float64),
			RefreshExpiresIn: result["refresh_expires_in"].(float64),
			RefreshToken:     result["refresh_token"].(string),
			TokenType:        result["token_type"].(string),
		}, nil
	}

	return nil, errors.New("Authentication failed")
}

/**
 * User List
 */
func (keycloakClient KeycloakClient) GetUserListInRealm(token *OIDCToken, realm string) (*[]KeycloakUser, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer " + token.AccessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/users")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakUser
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Groups of UserId
 */
func (keycloakClient KeycloakClient) GetUserGroupsInRealm(token *OIDCToken, realm string, userId string) (*[]KeycloakUserGroup, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer " + token.AccessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/users/" + userId + "/groups")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakUserGroup
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Group Role Mapping
 */
func (keycloakClient KeycloakClient) GetRoleMappingByGroupId(token *OIDCToken, realm string, groupId string) (*[]ClientRoleMapping, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer " + token.AccessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/groups/" + groupId + "/role-mappings")
	if err != nil {
		return nil, err
	}

	var result []ClientRoleMapping

	// Decode into struct
	var f map[string]interface{}
	if err := json.Unmarshal(resp.Body(), &f); err != nil {
		return nil, err
	}

	// JSON object parses into a map with string keys
	itemsMap := f["clientMappings"].(map[string]interface{})

	// Loop through the Items; we're not interested in the key, just the values
	for _, v := range itemsMap {
		// Use type assertions to ensure that the value's a JSON object
		switch jsonObj := v.(type) {
			// The value is an Item, represented as a generic interface
			case interface{}:
				jsonClientMapping, _ := json.Marshal(jsonObj)
				var client ClientRoleMapping
				if err := json.Unmarshal(jsonClientMapping, &client); err != nil {
					return nil, err
				}
				result = append(result, client)
			default:
				return nil, errors.New("Expecting a JSON object; got something else")
		}
	}

	return &result, nil
}

/**
 * Group List
 */
func (keycloakClient KeycloakClient) GetGroupListByRealm(token *OIDCToken, realm string) (*[]KeycloakGroup, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer " + token.AccessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/groups")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakGroup
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Roles by Realm
 */
func (keycloakClient KeycloakClient) GetRolesByRealm(token *OIDCToken, realm string) (*[]KeycloakRole, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer " + token.AccessToken).
		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/roles")
	if err != nil {
		return nil, err
	}

	// Decode into struct
	var result []KeycloakRole
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}

	return &result, nil
}

/**
 * Get Roles by Client and Realm
 */
func (keycloakClient KeycloakClient) GetRolesByClientId(token *OIDCToken, realm string, clientId string) (*[]KeycloakRole, error) {
 	resp, err := resty.R().
 		SetHeader("Content-Type", "application/json").
 		SetHeader("Authorization", "Bearer " + token.AccessToken).
 		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/clients/" + clientId + "/roles")
 	if err != nil {
 		return nil, err
 	}

 	// Decode into struct
 	var result []KeycloakRole
 	if err := json.Unmarshal(resp.Body(), &result); err != nil {
 		return nil, err
 	}

 	return &result, nil
}

/**
 * Get Clients by Realm
 */
func (keycloakClient KeycloakClient) GetClientsInRealm(token *OIDCToken, realm string) (*[]KeycloakRealmClient, error) {
 	resp, err := resty.R().
 		SetHeader("Content-Type", "application/json").
 		SetHeader("Authorization", "Bearer " + token.AccessToken).
 		Get(keycloakClient.Server + "/auth/admin/realms/" + realm + "/clients")
 	if err != nil {
 		return nil, err
 	}

 	// Decode into struct
 	var result []KeycloakRealmClient
 	if err := json.Unmarshal(resp.Body(), &result); err != nil {
 		return nil, err
 	}

 	return &result, nil
}

/**
 * Function to build the HttpBasicAuth Base64 String
 */
func getBasicAuthForClient(clientId string, clientSecret string) string {
	var httpBasicAuth string
	if len(clientId) > 0 && len(clientSecret) > 0 {
		httpBasicAuth = b64.URLEncoding.EncodeToString([]byte(clientId + ":" + clientSecret))
	}

	return "Basic " + httpBasicAuth
}
