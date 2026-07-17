// Package authz derives caller identity claims for CWB gRPC services.
//
// Historically, services trusted self-asserted "cwb-subject"/"cwb-org"/
// "cwb-scopes" gRPC metadata even though connections are already
// authenticated with per-identity mTLS client certificates (mode
// "metadata" below preserves that legacy behavior). Mode "cert" instead
// derives the caller's identity from the verified peer certificate's
// Common Name and cross-checks any asserted metadata against a per-service
// grant table, so a mesh-cert holder can no longer claim an arbitrary
// org/scope set. A small set of trusted proxies (gateways that legitimately
// act on behalf of other callers, e.g. interchange, nexus-broker) are
// exempted and continue to be trusted on their metadata.
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// Metadata keys carrying self-asserted (legacy) or cross-checked (cert mode)
// caller identity.
const (
	mdSubjectKey = "cwb-subject"
	mdOrgKey     = "cwb-org"
	mdScopesKey  = "cwb-scopes"
)

// Sentinel errors returned by Identify. Use errors.Is to test for them.
var (
	// ErrNoPeerCert is returned in cert mode when the incoming context
	// carries no peer, no TLS transport credentials, or no verified
	// client certificate chain.
	ErrNoPeerCert = errors.New("authz: no verified peer certificate")

	// ErrUnknownIdentity is returned in cert mode when the peer
	// certificate's Common Name has no entry in Config.Grants.
	ErrUnknownIdentity = errors.New("authz: unknown peer identity")

	// ErrMismatch is returned when asserted metadata (subject, org, or
	// scopes) conflicts with, or exceeds, the caller's verified identity
	// or grant.
	ErrMismatch = errors.New("authz: identity assertion mismatch")

	// ErrNoIdentity is returned when required identity information is
	// absent: metadata mode is always missing cwb-subject/cwb-org, or
	// cert mode cannot determine a single org for a multi-org grant
	// without an explicit cwb-org assertion.
	ErrNoIdentity = errors.New("authz: no identity presented")

	// ErrBadMode is returned when Config.Mode is not "metadata" or
	// "cert".
	ErrBadMode = errors.New("authz: unknown mode")
)

// Claims describes the authenticated caller.
type Claims struct {
	// Sub is the caller's subject identifier: in metadata mode, the
	// asserted cwb-subject; in cert mode, the verified peer certificate
	// Common Name (or, for a trusted proxy, the asserted cwb-subject).
	Sub string
	// Org is the caller's organization id/slug.
	Org string
	// Scopes is the caller's effective, granted scope set.
	Scopes []string
}

// Grant describes what a peer-certificate Common Name is permitted to
// assert in cert mode.
type Grant struct {
	// Orgs lists the org ids/slugs this identity may act as. A single
	// element "*" permits any org.
	Orgs []string
	// Scopes lists the scope strings this identity may hold.
	Scopes []string
}

// Config configures identity derivation.
type Config struct {
	// Mode selects the trust model: "metadata" (legacy, self-asserted)
	// or "cert" (verified peer certificate plus grant table).
	Mode string
	// Grants maps peer-certificate Common Name to its permitted
	// orgs/scopes. Only consulted in cert mode.
	Grants map[string]Grant
	// TrustedProxies lists peer Common Names whose asserted metadata is
	// authoritative, bypassing grant lookup entirely. Only consulted in
	// cert mode.
	TrustedProxies map[string]bool
}

// Identify derives the caller's Claims from ctx per cfg.Mode. It returns
// the derived Claims, the effective scopes (identical to Claims.Scopes,
// returned separately so the (claims, scopes, _) prefix lines up with
// services' prior identityFromMD helpers and adoption is mechanical), and
// an error on failure — one of the sentinel errors above, some of which
// are returned wrapped (fmt.Errorf("%w: ...")) with context and so must be
// matched with errors.Is, not ==.
func Identify(ctx context.Context, cfg Config) (*Claims, []string, error) {
	switch cfg.Mode {
	case "metadata":
		claims, err := identifyFromMetadata(ctx)
		if err != nil {
			return nil, nil, err
		}
		return claims, claims.Scopes, nil
	case "cert":
		claims, err := identifyFromCert(ctx, cfg)
		if err != nil {
			return nil, nil, err
		}
		return claims, claims.Scopes, nil
	default:
		return nil, nil, fmt.Errorf("%w: %q", ErrBadMode, cfg.Mode)
	}
}

func identifyFromMetadata(ctx context.Context) (*Claims, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	sub := firstMD(md, mdSubjectKey)
	org := firstMD(md, mdOrgKey)
	if sub == "" || org == "" {
		return nil, ErrNoIdentity
	}
	return &Claims{
		Sub:    sub,
		Org:    org,
		Scopes: strings.Fields(firstMD(md, mdScopesKey)),
	}, nil
}

func identifyFromCert(ctx context.Context, cfg Config) (*Claims, error) {
	cn, err := peerCommonName(ctx)
	if err != nil {
		return nil, err
	}

	if cfg.TrustedProxies[cn] {
		// The proxy has already authenticated the real caller
		// upstream; its metadata assertion is authoritative.
		return identifyFromMetadata(ctx)
	}

	grant, ok := cfg.Grants[cn]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownIdentity, cn)
	}

	md, _ := metadata.FromIncomingContext(ctx)

	if sub := firstMD(md, mdSubjectKey); sub != "" && sub != cn {
		return nil, fmt.Errorf("%w: subject %q does not match peer certificate %q", ErrMismatch, sub, cn)
	}

	org, err := resolveOrg(md, grant)
	if err != nil {
		return nil, err
	}

	scopes, err := resolveScopes(md, grant)
	if err != nil {
		return nil, err
	}

	return &Claims{Sub: cn, Org: org, Scopes: scopes}, nil
}

func resolveOrg(md metadata.MD, grant Grant) (string, error) {
	org := firstMD(md, mdOrgKey)
	if org == "" {
		if len(grant.Orgs) == 1 && grant.Orgs[0] != "*" {
			return grant.Orgs[0], nil
		}
		return "", ErrNoIdentity
	}
	if orgAllowed(grant, org) {
		return org, nil
	}
	return "", fmt.Errorf("%w: org %q not permitted for this identity", ErrMismatch, org)
}

func orgAllowed(grant Grant, org string) bool {
	for _, o := range grant.Orgs {
		if o == "*" || o == org {
			return true
		}
	}
	return false
}

func resolveScopes(md metadata.MD, grant Grant) ([]string, error) {
	requested := strings.Fields(firstMD(md, mdScopesKey))
	if len(requested) == 0 {
		return grant.Scopes, nil
	}
	granted := make(map[string]bool, len(grant.Scopes))
	for _, s := range grant.Scopes {
		granted[s] = true
	}
	for _, s := range requested {
		if !granted[s] {
			return nil, fmt.Errorf("%w: scope %q not permitted for this identity", ErrMismatch, s)
		}
	}
	return requested, nil
}

// PeerCommonName returns the CommonName of the verified peer certificate on
// the connection, or ErrNoPeerCert when the transport has no verified client
// cert (plaintext, or TLS without client verification). Services use it to
// attribute denial audits to the proven identity; authorization decisions
// belong to Identify.
func PeerCommonName(ctx context.Context) (string, error) {
	return peerCommonName(ctx)
}

func peerCommonName(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return "", ErrNoPeerCert
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", ErrNoPeerCert
	}
	chains := tlsInfo.State.VerifiedChains
	if len(chains) == 0 || len(chains[0]) == 0 {
		return "", ErrNoPeerCert
	}
	return chains[0][0].Subject.CommonName, nil
}

func firstMD(md metadata.MD, key string) string {
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// ParseGrants parses a grant table from its wire/config format:
//
//	subject=orgs:o1,o2;scopes:s1,s2|subject2=orgs:*;scopes:s3
//
// Whitespace around subjects, keys, and values is trimmed. A subject
// appearing more than once, an entry missing orgs or scopes, or an entry
// with an empty orgs/scopes value is an error. Scope (and org) values may
// themselves contain colons; only the first colon after "orgs"/"scopes"
// separates the section key from its comma-separated value list.
func ParseGrants(s string) (map[string]Grant, error) {
	grants := make(map[string]Grant)
	s = strings.TrimSpace(s)
	if s == "" {
		return grants, nil
	}
	for _, entry := range strings.Split(s, "|") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		subject, rest, ok := strings.Cut(entry, "=")
		subject = strings.TrimSpace(subject)
		if !ok || subject == "" || rest == "" {
			return nil, fmt.Errorf("authz: malformed grant entry %q", entry)
		}
		if _, dup := grants[subject]; dup {
			return nil, fmt.Errorf("authz: duplicate grant subject %q", subject)
		}

		grant := Grant{}
		haveOrgs, haveScopes := false, false
		for _, section := range strings.Split(rest, ";") {
			section = strings.TrimSpace(section)
			if section == "" {
				continue
			}
			key, val, ok := strings.Cut(section, ":")
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			if !ok || val == "" {
				return nil, fmt.Errorf("authz: malformed grant section %q for subject %q", section, subject)
			}
			values := splitTrimmed(val, ",")
			if len(values) == 0 {
				return nil, fmt.Errorf("authz: empty %q section for subject %q", key, subject)
			}
			switch key {
			case "orgs":
				grant.Orgs = values
				haveOrgs = true
			case "scopes":
				grant.Scopes = values
				haveScopes = true
			default:
				return nil, fmt.Errorf("authz: unknown grant section %q for subject %q", key, subject)
			}
		}
		if !haveOrgs || !haveScopes {
			return nil, fmt.Errorf("authz: grant for subject %q missing orgs or scopes", subject)
		}
		grants[subject] = grant
	}
	return grants, nil
}

// ParseProxies parses a comma-separated list of trusted-proxy peer
// Common Names. Whitespace is trimmed and empty entries are dropped.
func ParseProxies(s string) map[string]bool {
	proxies := make(map[string]bool)
	for _, cn := range strings.Split(s, ",") {
		cn = strings.TrimSpace(cn)
		if cn == "" {
			continue
		}
		proxies[cn] = true
	}
	return proxies
}

func splitTrimmed(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}
