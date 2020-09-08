package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/davidalvarezcastro/bookstore-oauth-go/oauth/errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientID = "X-Client-Id"
	headerXCallerID = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8081",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int64  `json:"user_id"`
	ClientID int64  `json:"client_id"`
}

// IsPublic returns true if a request is public
func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

// GetCallerID returns the caller id from the request
func GetCallerID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerID), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

// GetClientID returns the client id from the request
func GetClientID(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientID), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

// AuthenticateRequest tries to authenticate
func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessToken := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessToken == "" {
		return nil
	}

	at, err := getAccessToken(accessToken)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}

		return err
	}

	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenID string) (*accessToken, *errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenID))
	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("invalid restclient response when trying to get access token")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			return nil, errors.NewInternalServerError("invalid error interface when trying to get access token")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal access token response")
	}
	return &at, nil
}
