package conformance_test

import (
	"context"
	"fmt"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

// gatewayAPIGroup is the CRD group every kind below belongs to.
const gatewayAPIGroup = "gateway.networking.k8s.io"

// clusterCapabilities describes what the installed Gateway API CRDs actually
// serve, so this suite declares the same reduced feature set Coxswain does.
//
// Gateway API CRDs are cluster-scoped singletons, so a cluster can be pinned to
// an older release by a co-resident implementation. Both the profile list and
// the feature list are therefore derived from the cluster rather than compiled
// in — declaring a feature whose CRD or schema field is absent fails
// conformance on a cluster that is behaving correctly.
type clusterCapabilities struct {
	// kinds holds the plural resource name of every Gateway API CRD that
	// *serves a version Coxswain watches*. Presence of the CRD alone is not
	// enough: the experimental channel ships TLSRoute at v1alpha2/v1alpha3
	// only until Gateway API v1.5, and Coxswain watches v1 — so a
	// presence-only oracle would declare a feature nothing is watching.
	kinds map[string]bool
	// fields holds probe names whose schema path resolved. Kind presence alone
	// cannot answer these: `httproutes` exists at every supported version, but
	// its `cors` filter does not.
	fields map[string]bool
}

func (c clusterCapabilities) hasKind(plural string) bool { return c.kinds[plural] }
func (c clusterCapabilities) hasField(name string) bool  { return c.fields[name] }

// watchedVersions lists, per plural resource name, the API versions Coxswain
// watches — mirroring `GatewayApiKind::versions()` on the Rust side. A CRD that
// serves none of them is not usable, however installed it looks.
var watchedVersions = map[string][]string{
	"gatewayclasses":     {"v1", "v1beta1"},
	"gateways":           {"v1", "v1beta1"},
	"httproutes":         {"v1", "v1beta1"},
	"grpcroutes":         {"v1"},
	"referencegrants":    {"v1", "v1beta1"},
	"backendtlspolicies": {"v1"},
	"listenersets":       {"v1"},
	"tlsroutes":          {"v1"},
	"tcproutes":          {"v1"},
	"udproutes":          {"v1"},
}

// servesWatchedVersion reports whether the CRD serves a version Coxswain
// watches. Only `served: true` versions count — a CRD may retain a legacy
// version with `served: false`.
func servesWatchedVersion(crd *apiextv1.CustomResourceDefinition) bool {
	wanted, known := watchedVersions[crd.Spec.Names.Plural]
	if !known {
		return false
	}
	for i := range crd.Spec.Versions {
		version := &crd.Spec.Versions[i]
		if !version.Served {
			continue
		}
		for _, w := range wanted {
			if version.Name == w {
				return true
			}
		}
	}
	return false
}

// schemaProbe locates one optional field inside a CRD's structural schema.
//
// `path` is a sequence of property names walked from the root of the served
// version's `openAPIV3Schema`, descending through `items` implicitly wherever a
// node is an array — so the path reads as plain field names regardless of how
// many list hops it crosses.
type schemaProbe struct {
	name string
	crd  string
	path []string
}

// The field-gated features. Each mirrors an entry in the Rust
// `GatewayApiField` vocabulary; the two lists exist because the Go suite and
// the Rust controller must agree about the same cluster.
var schemaProbes = []schemaProbe{
	// GEP-1767: the CORS filter, added in Gateway API v1.5.
	{name: "HTTPRouteCORS", crd: "httproutes." + gatewayAPIGroup, path: []string{"spec", "rules", "filters", "cors"}},
	// GEP-91: frontend client-certificate validation, added in Gateway API v1.5.
	{name: "GatewayFrontendTLS", crd: "gateways." + gatewayAPIGroup, path: []string{"spec", "tls", "frontend"}},
}

// detectCapabilities reads the installed CRDs directly.
//
// Discovery would answer kind presence, but not whether `httproutes` carries a
// `cors` filter — so both halves come from the CRD objects, one read per CRD.
func detectCapabilities(ctx context.Context) (clusterCapabilities, error) {
	caps := clusterCapabilities{kinds: map[string]bool{}, fields: map[string]bool{}}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		return caps, fmt.Errorf("build kubeconfig: %w", err)
	}
	client, err := apiextclient.NewForConfig(cfg)
	if err != nil {
		return caps, fmt.Errorf("build apiextensions client: %w", err)
	}

	crds, err := client.ApiextensionsV1().CustomResourceDefinitions().List(ctx, metav1.ListOptions{})
	if err != nil {
		return caps, fmt.Errorf("list CRDs: %w", err)
	}
	for i := range crds.Items {
		crd := &crds.Items[i]
		if crd.Spec.Group != gatewayAPIGroup || !servesWatchedVersion(crd) {
			continue
		}
		caps.kinds[crd.Spec.Names.Plural] = true
	}

	for _, probe := range schemaProbes {
		crd, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, probe.crd, metav1.GetOptions{})
		if err != nil {
			// An uninstalled CRD simply has none of its fields; anything else
			// means we could not read the cluster and must not guess.
			if apierrors.IsNotFound(err) {
				continue
			}
			return caps, fmt.Errorf("get CRD %s: %w", probe.crd, err)
		}
		if crdDeclaresField(crd, probe.path) {
			caps.fields[probe.name] = true
		}
	}
	return caps, nil
}

// crdDeclaresField reports whether any served version's schema declares `path`.
//
// Only served versions count: a CRD may retain a legacy version with
// `served: false`, and a field removed from every served version is gone.
func crdDeclaresField(crd *apiextv1.CustomResourceDefinition, path []string) bool {
	for i := range crd.Spec.Versions {
		version := &crd.Spec.Versions[i]
		if !version.Served || version.Schema == nil || version.Schema.OpenAPIV3Schema == nil {
			continue
		}
		if resolveSchemaPath(version.Schema.OpenAPIV3Schema, path) {
			return true
		}
	}
	return false
}

// resolveSchemaPath walks `path` from `root`, descending through `items` for
// array nodes.
//
// A name that fails to resolve at *any* depth means the field is absent, not
// that the schema is malformed — Gateway API v1.4 `Gateway` has no `spec.tls`
// subtree at all, so the intermediate hop is the one that fails there.
func resolveSchemaPath(root *apiextv1.JSONSchemaProps, path []string) bool {
	node := root
	for _, name := range path {
		next := descend(node, name)
		if next == nil {
			return false
		}
		node = next
	}
	return true
}

// descend resolves one property name, stepping into `items` first when the
// current node is an array.
func descend(node *apiextv1.JSONSchemaProps, name string) *apiextv1.JSONSchemaProps {
	if prop, ok := node.Properties[name]; ok {
		return &prop
	}
	if node.Items != nil {
		if node.Items.Schema != nil {
			return descend(node.Items.Schema, name)
		}
		for i := range node.Items.JSONSchemas {
			if found := descend(&node.Items.JSONSchemas[i], name); found != nil {
				return found
			}
		}
	}
	return nil
}
