package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"

	"github.com/sosedoff/pgweb/pkg/shared"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

func TestClientTakeTunnel(t *testing.T) {
	tunnel := &Tunnel{}

	oldClient := &Client{tunnel: tunnel}
	newClient := &Client{}

	newClient.TakeTunnel(oldClient)
	assert.Equal(t, tunnel, newClient.tunnel)
	assert.Nil(t, oldClient.tunnel)

	// Closing the old client must not tear down the tunnel it gave away
	assert.NoError(t, oldClient.Close())
	assert.Equal(t, tunnel, newClient.tunnel)

	// Nothing to take from a client without a tunnel, or from nil
	other := &Client{}
	newClient.TakeTunnel(other)
	newClient.TakeTunnel(nil)
	assert.Equal(t, tunnel, newClient.tunnel)
}

func TestMakeConfigWithKeyData(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	block, err := ssh.MarshalPrivateKey(priv, "")
	assert.NoError(t, err)
	pemData := string(pem.EncodeToMemory(block))

	// Key contents take precedence over a (bogus) path
	cfg, err := makeConfig(&shared.SSHInfo{User: "u", Key: "/does/not/exist", KeyData: pemData})
	assert.NoError(t, err)
	assert.Len(t, cfg.Auth, 1)

	_, err = makeConfig(&shared.SSHInfo{User: "u", KeyData: "not a key"})
	assert.Error(t, err)
}
