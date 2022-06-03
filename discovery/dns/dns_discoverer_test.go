package discovery

import (
	"context"
	"testing"

	"github.com/mailio/go-mailio-core-modules/errors"
	"github.com/stretchr/testify/assert"
)

const DOMAIN = "mail.io"

var disc = NewDiscoverer()

// the test uses mail.io for testing
func TestDiscover(t *testing.T) {
	discover, err := disc.Discover(context.Background(), DOMAIN)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, discover.Domain, DOMAIN)
	assert.Equal(t, discover.IsMailio, true)
	assert.Equal(t, discover.PublicKeyType, "ed25519")
}

func TestPublicKey(t *testing.T) {
	key := "5uW7anEGF1nIjGfp5pS2kiN0cn2mGYkuSa+TCBoFIbQ="
	pkErr := disc.validatePublicKey(key)
	if pkErr != nil {
		t.Fatal(pkErr)
	}
}

func TestPublicKeyTooShort(t *testing.T) {
	key := "" // valid base64
	pkErr := disc.validatePublicKey(key)
	assert.Equal(t, pkErr, errors.ErrInvalidPublicKey)
}
