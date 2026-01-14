// Package imageref provides shared utilities for extracting and processing
// container image references from Kubernetes pod specifications.
package imageref

import (
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// DefaultKeychain returns a keychain that supports multiple credential sources:
// 1. Docker config.json credentials (authn.DefaultKeychain)
// 2. Azure Container Registry (ACR) credentials via environment variables or MSI
//
// This keychain enables authentication to:
// - Any registry with credentials stored in ~/.docker/config.json
// - Azure Container Registry using:
//   - Service Principal (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
//   - Federated OIDC (AZURE_CLIENT_ID, AZURE_FEDERATED_TOKEN, AZURE_TENANT_ID)
//   - Managed Service Identity (automatic in Azure environments)
//
// The keychains are tried in order; the first one to provide credentials wins.
func DefaultKeychain() authn.Keychain {
	return authn.NewMultiKeychain(
		authn.DefaultKeychain,
		authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper()),
	)
}

// DefaultRemoteOptions returns a set of remote.Option that includes
// authentication from the DefaultKeychain.
func DefaultRemoteOptions() []remote.Option {
	return []remote.Option{
		remote.WithAuthFromKeychain(DefaultKeychain()),
	}
}
