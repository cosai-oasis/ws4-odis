// Command apf-bundle-issuer is the Vault external secrets-engine plugin that issues
// transit-signed APF Signed Policy Bundles for validated workload-identity JWTs.
package main

import (
	"odis-contract-harness/vault-plugin/backend"
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	meta := &api.PluginAPIClientMeta{}
	flags := meta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		hclog.L().Error("failed to parse plugin args", "error", err)
		os.Exit(1)
	}

	tlsProvider := api.VaultPluginTLSProvider(meta.GetTLSConfig())
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    tlsProvider,
	}); err != nil {
		hclog.L().Error("apf-bundle-issuer plugin exiting", "error", err)
		os.Exit(1)
	}
}
