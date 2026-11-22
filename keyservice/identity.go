package keyservice

import (
	"context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// CallerIdentity describes the authenticated identity of a key service caller.
//
// An identity is only marked Authenticated when the gRPC connection presented
// a client certificate that was verified against the configured client CA.
// Anonymous callers have Authenticated set to false. Callers that reach the
// server without a gRPC peer at all (the in-process LocalClient) have Local
// set to true; they never traverse the network and are not subject to
// transport authentication or scope rules.
type CallerIdentity struct {
	// Local is true for in-process calls made through LocalClient.
	Local bool
	// Authenticated is true when a verified client certificate was presented.
	Authenticated bool
	// Anonymous is true for non-local, unauthenticated callers that were
	// admitted by the explicit anonymous mode.
	Anonymous bool
	// CommonName is the subject common name of the verified client cert.
	CommonName string
	// DNSNames and URIs are the subject alternative names of the client cert.
	DNSNames []string
	URIs     []string
	// Peer is the network address of the caller, when available.
	Peer string
}

// CallerID returns a stable, human-readable identifier for audit records.
func (id CallerIdentity) CallerID() string {
	switch {
	case id.Local:
		return "local"
	case id.Anonymous || !id.Authenticated:
		return "anonymous"
	case id.CommonName != "":
		return id.CommonName
	case len(id.DNSNames) > 0:
		return id.DNSNames[0]
	case len(id.URIs) > 0:
		return id.URIs[0]
	default:
		return "authenticated"
	}
}

// candidates returns the strings a scope rule may use to refer to this
// identity. Both the bare value and the prefixed form are accepted, so a rule
// may say either "ops-client" or "CN=ops-client".
func (id CallerIdentity) candidates() []string {
	if id.Local {
		return []string{"local", "*"}
	}
	if !id.Authenticated {
		if id.Anonymous {
			return []string{"anonymous"}
		}
		return nil
	}
	var out []string
	add := func(prefix, value string) {
		if value == "" {
			return
		}
		out = append(out, value)
		if prefix != "" {
			out = append(out, prefix+"="+value)
		}
	}
	add("CN", id.CommonName)
	for _, name := range id.DNSNames {
		add("DNS", name)
	}
	for _, uri := range id.URIs {
		add("URI", uri)
	}
	return out
}

// CallerFromContext extracts the caller identity from the gRPC peer stored in
// ctx. When ctx has no gRPC peer the call is in-process (LocalClient) and the
// returned identity has Local set.
func CallerFromContext(ctx context.Context) CallerIdentity {
	if ctx == nil {
		return CallerIdentity{Local: true}
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return CallerIdentity{Local: true}
	}
	id := CallerIdentity{}
	if p.Addr != nil {
		id.Peer = p.Addr.String()
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return id
	}
	leaf := tlsInfo.State.VerifiedChains[0][0]
	id.Authenticated = true
	id.CommonName = leaf.Subject.CommonName
	id.DNSNames = append(id.DNSNames, leaf.DNSNames...)
	for _, uri := range leaf.URIs {
		id.URIs = append(id.URIs, uri.String())
	}
	return id
}
