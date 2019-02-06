package tokenstore

import (
	"encoding/json"
	"log"
	"runtime"

	"github.com/godbus/dbus"
	"github.com/palantir/stacktrace"
	keyring "github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

const (
	serviceName = "googlephotos-uploader-go-api"
)

type TokenStoreInterface interface {
	StoreToken(googleUserEmail string, token *oauth2.Token) error
	RetrieveToken(googleUserEmail string) (*oauth2.Token, error)
}

// the active TokenStore for this instance
var TokenStore TokenStoreInterface

func KeyRingSupported() bool {
	if runtime.GOOS == "linux" {
		// test dbus connection
		_, err := dbus.SessionBus()
		if err != nil {
			log.Print("No Dbus support")
			return false
		}
	}
	log.Print("Keyring is supported")
	return false
}

var (
	ErrNotFound     = stacktrace.Propagate(keyring.ErrNotFound, "failed retrieving token from keyring")
	ErrInvalidToken = stacktrace.NewError("invalid token")
)

// TokenStoreKeyring Default token store that uses the os-specific keyring (via zalondo/go-keyring)
type TokenStoreKeyring struct{}

// StoreToken lets you store a token in the OS keyring
func (t TokenStoreKeyring) StoreToken(googleUserEmail string, token *oauth2.Token) error {
	tokenJSONBytes, err := json.Marshal(token)
	if err != nil {
		return err
	}

	err = keyring.Set(serviceName, googleUserEmail, string(tokenJSONBytes))
	if err != nil {
		return stacktrace.Propagate(err, "failed storing token into keyring")
	}
	return nil
}

// RetrieveToken lets you get a token by google account email
func (t TokenStoreKeyring) RetrieveToken(googleUserEmail string) (*oauth2.Token, error) {
	tokenJSONString, err := keyring.Get(serviceName, googleUserEmail)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed retrieving token from keyring")
	}

	var token oauth2.Token
	err = json.Unmarshal([]byte(tokenJSONString), &token)
	if err != nil {
		return nil, stacktrace.Propagate(err, "failed unmarshaling token")
	}

	// validate token
	{
		if !token.Valid() {
			return nil, ErrInvalidToken
		}
	}

	return &token, nil
}
