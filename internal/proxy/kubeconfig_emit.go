package proxy

import (
	"fmt"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// EmitSandboxKubeconfig builds a self-contained kubeconfig YAML for a
// remote consumer (e.g. an agent container). The result points at
// `serverURL`, authenticates with `bearerToken`, and trusts the embedded
// CA certificate.
//
// `contextName` is used as the cluster/context/user identifier inside
// the file and is what `kubectl config current-context` will report.
// `serverURL` should include the scheme (https://) and the
// host[:port] reachable from the consumer's network (the --advertise
// address, not the proxy's bind address).
func EmitSandboxKubeconfig(serverURL, contextName, bearerToken string, caPEM []byte) ([]byte, error) {
	if serverURL == "" || contextName == "" || bearerToken == "" || len(caPEM) == 0 {
		return nil, fmt.Errorf("EmitSandboxKubeconfig: serverURL, contextName, bearerToken, and caPEM are all required")
	}
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[contextName] = &clientcmdapi.Cluster{
		Server:                   serverURL,
		CertificateAuthorityData: caPEM,
	}
	cfg.AuthInfos[contextName] = &clientcmdapi.AuthInfo{
		Token: bearerToken,
	}
	cfg.Contexts[contextName] = &clientcmdapi.Context{
		Cluster:  contextName,
		AuthInfo: contextName,
	}
	cfg.CurrentContext = contextName

	out, err := clientcmd.Write(*cfg)
	if err != nil {
		return nil, fmt.Errorf("serialize sandbox kubeconfig: %w", err)
	}
	return out, nil
}
