package proxy

import (
	"fmt"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// EmitSandboxKubeconfig builds a self-contained kubeconfig YAML for a
// remote consumer (e.g. an agent container). The result points at
// `serverURL`, authenticates with `bearerToken`, and (when caPEM is
// non-empty) trusts the embedded CA certificate.
//
// `contextName` is used as the cluster/context/user identifier inside
// the file and is what `kubectl config current-context` will report.
// `serverURL` should include the scheme (https://) and the
// host[:port] reachable from the consumer's network (the --advertise
// address, not the proxy's bind address).
//
// `caPEM` may be empty when serverURL uses http:// (plaintext proxies
// for loopback testing). For https:// callers it must be supplied.
func EmitSandboxKubeconfig(serverURL, contextName, bearerToken string, caPEM []byte) ([]byte, error) {
	switch {
	case serverURL == "":
		return nil, fmt.Errorf("EmitSandboxKubeconfig: serverURL is required")
	case contextName == "":
		return nil, fmt.Errorf("EmitSandboxKubeconfig: contextName is required")
	case bearerToken == "":
		return nil, fmt.Errorf("EmitSandboxKubeconfig: bearerToken is required")
	}
	cluster := &clientcmdapi.Cluster{Server: serverURL}
	if len(caPEM) > 0 {
		cluster.CertificateAuthorityData = caPEM
	}
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters[contextName] = cluster
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
