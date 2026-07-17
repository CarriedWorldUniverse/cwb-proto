package authz_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"reflect"
	"sort"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/CarriedWorldUniverse/cwb-proto/authz"
)

// ---- ParseGrants / ParseProxies ---------------------------------------

func TestParseGrants(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		in := "croft=orgs:carriedworld,07244ac5-1fbd-4786-9301-a925f4241306;scopes:cred:read,cred:write|" +
			"operator=orgs:*;scopes:admin:write"
		got, err := authz.ParseGrants(in)
		if err != nil {
			t.Fatalf("ParseGrants: %v", err)
		}
		want := map[string]authz.Grant{
			"croft": {
				Orgs:   []string{"carriedworld", "07244ac5-1fbd-4786-9301-a925f4241306"},
				Scopes: []string{"cred:read", "cred:write"},
			},
			"operator": {
				Orgs:   []string{"*"},
				Scopes: []string{"admin:write"},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	})

	t.Run("wildcard org", func(t *testing.T) {
		got, err := authz.ParseGrants("x=orgs:*;scopes:a")
		if err != nil {
			t.Fatalf("ParseGrants: %v", err)
		}
		if got["x"].Orgs[0] != "*" {
			t.Fatalf("expected wildcard org, got %#v", got["x"])
		}
	})

	t.Run("duplicate subject error", func(t *testing.T) {
		_, err := authz.ParseGrants("x=orgs:a;scopes:s|x=orgs:b;scopes:t")
		if err == nil {
			t.Fatal("expected error for duplicate subject")
		}
	})

	t.Run("malformed entry error", func(t *testing.T) {
		for _, bad := range []string{
			"noequals",
			"x=orgs:a",             // missing scopes
			"x=scopes:a",           // missing orgs
			"x=orgs:;scopes:a",     // empty orgs value
			"x=orgs:a;scopes:",     // empty scopes value
			"=orgs:a;scopes:b",     // empty subject
			"x=unknown:a;scopes:b", // unknown section
		} {
			if _, err := authz.ParseGrants(bad); err == nil {
				t.Errorf("ParseGrants(%q): expected error, got nil", bad)
			}
		}
	})

	t.Run("scope with colon round-trips", func(t *testing.T) {
		got, err := authz.ParseGrants("x=orgs:o;scopes:cred:read,cred:write")
		if err != nil {
			t.Fatalf("ParseGrants: %v", err)
		}
		want := []string{"cred:read", "cred:write"}
		if !reflect.DeepEqual(got["x"].Scopes, want) {
			t.Fatalf("got %#v, want %#v", got["x"].Scopes, want)
		}
	})
}

func TestParseProxies(t *testing.T) {
	got := authz.ParseProxies(" interchange , nexus-broker ,, ")
	want := map[string]bool{"interchange": true, "nexus-broker": true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	if empty := authz.ParseProxies(""); len(empty) != 0 {
		t.Fatalf("expected empty map, got %#v", empty)
	}
}

// ---- metadata-mode Identify (no gRPC transport needed) -----------------

func TestIdentifyMetadataMode(t *testing.T) {
	cfg := authz.Config{Mode: "metadata"}

	t.Run("present", func(t *testing.T) {
		md := metadata.Pairs("cwb-subject", "alice", "cwb-org", "carriedworld", "cwb-scopes", "cred:read cred:write")
		ctx := metadata.NewIncomingContext(context.Background(), md)
		claims, scopes, err := authz.Identify(ctx, cfg)
		if err != nil {
			t.Fatalf("Identify: %v", err)
		}
		if claims.Sub != "alice" || claims.Org != "carriedworld" {
			t.Fatalf("unexpected claims: %#v", claims)
		}
		want := []string{"cred:read", "cred:write"}
		if !reflect.DeepEqual(scopes, want) || !reflect.DeepEqual(claims.Scopes, want) {
			t.Fatalf("unexpected scopes: %#v / %#v", scopes, claims.Scopes)
		}
	})

	t.Run("absent subject", func(t *testing.T) {
		md := metadata.Pairs("cwb-org", "carriedworld")
		ctx := metadata.NewIncomingContext(context.Background(), md)
		_, _, err := authz.Identify(ctx, cfg)
		if !errors.Is(err, authz.ErrNoIdentity) {
			t.Fatalf("got %v, want ErrNoIdentity", err)
		}
	})

	t.Run("absent org", func(t *testing.T) {
		md := metadata.Pairs("cwb-subject", "alice")
		ctx := metadata.NewIncomingContext(context.Background(), md)
		_, _, err := authz.Identify(ctx, cfg)
		if !errors.Is(err, authz.ErrNoIdentity) {
			t.Fatalf("got %v, want ErrNoIdentity", err)
		}
	})

	t.Run("absent both", func(t *testing.T) {
		_, _, err := authz.Identify(context.Background(), cfg)
		if !errors.Is(err, authz.ErrNoIdentity) {
			t.Fatalf("got %v, want ErrNoIdentity", err)
		}
	})
}

func TestIdentifyBadMode(t *testing.T) {
	_, _, err := authz.Identify(context.Background(), authz.Config{Mode: "bogus"})
	if !errors.Is(err, authz.ErrBadMode) {
		t.Fatalf("got %v, want ErrBadMode", err)
	}
}

// ---- cert-mode Identify over a real gRPC/TLS connection -----------------

// jsonCodec lets the test avoid depending on generated protobuf types: it
// marshals/unmarshals the trivial testMsg via encoding/json and is
// registered under grpc's default codec name "proto" so no special
// per-call options are required.
type jsonCodec struct{}

func (jsonCodec) Marshal(v interface{}) ([]byte, error) { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
func (jsonCodec) Name() string { return "proto" }

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

type testMsg struct {
	Sub    string   `json:"sub,omitempty"`
	Org    string   `json:"org,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
	Err    string   `json:"err,omitempty"`
}

type identifyServer struct {
	cfg authz.Config
}

func (s *identifyServer) Identify(ctx context.Context, _ *testMsg) (*testMsg, error) {
	claims, scopes, err := authz.Identify(ctx, s.cfg)
	if err != nil {
		return &testMsg{Err: errKind(err)}, nil
	}
	return &testMsg{Sub: claims.Sub, Org: claims.Org, Scopes: scopes}, nil
}

// errKind maps a returned error to a stable sentinel name so the client
// can assert on it without depending on grpc status/error wire encoding.
func errKind(err error) string {
	switch {
	case errors.Is(err, authz.ErrNoPeerCert):
		return "ErrNoPeerCert"
	case errors.Is(err, authz.ErrUnknownIdentity):
		return "ErrUnknownIdentity"
	case errors.Is(err, authz.ErrMismatch):
		return "ErrMismatch"
	case errors.Is(err, authz.ErrNoIdentity):
		return "ErrNoIdentity"
	case errors.Is(err, authz.ErrBadMode):
		return "ErrBadMode"
	default:
		return "unknown: " + err.Error()
	}
}

var testServiceDesc = grpc.ServiceDesc{
	ServiceName: "authz.Test",
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Identify",
			Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor) (interface{}, error) {
				in := new(testMsg)
				if err := dec(in); err != nil {
					return nil, err
				}
				return srv.(*identifyServer).Identify(ctx, in)
			},
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "authz_test.proto",
}

// ---- test PKI -------------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leaf issues a certificate+key for cn, signed by the CA. If server is
// true, it is suitable for use as a TLS server certificate (adds a
// DNS SAN of "localhost").
func (ca *testCA) leaf(t *testing.T, cn string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key for %s: %v", cn, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf cert for %s: %v", cn, err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

// ---- test harness -----------------------------------------------------

const bufSize = 1024 * 1024

// startMTLSServer starts an in-process gRPC server requiring and
// verifying client certificates, running cfg's Identify logic on each
// call. It returns a dialer usable with grpc.WithContextDialer plus the
// CA to trust and a teardown func.
func startMTLSServer(t *testing.T, ca *testCA, cfg authz.Config) (dial func(context.Context, string) (net.Conn, error), stop func()) {
	t.Helper()
	lis := bufconn.Listen(bufSize)

	serverCert := ca.leaf(t, "test-server", true)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
		MinVersion:   tls.VersionTLS12,
	}

	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	srv.RegisterService(&testServiceDesc, &identifyServer{cfg: cfg})

	go func() {
		_ = srv.Serve(lis)
	}()

	return func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}, func() {
			srv.Stop()
		}
}

// startPlaintextServer starts an in-process gRPC server with no TLS at
// all, used to exercise the "no peer cert" path.
func startPlaintextServer(t *testing.T, cfg authz.Config) (dial func(context.Context, string) (net.Conn, error), stop func()) {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	srv.RegisterService(&testServiceDesc, &identifyServer{cfg: cfg})
	go func() {
		_ = srv.Serve(lis)
	}()
	return func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}, func() {
			srv.Stop()
		}
}

func dialMTLS(t *testing.T, ca *testCA, dial func(context.Context, string) (net.Conn, error), clientCert tls.Certificate) *grpc.ClientConn {
	t.Helper()
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      ca.pool,
		ServerName:   "localhost",
	}
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func dialPlaintext(t *testing.T, dial func(context.Context, string) (net.Conn, error)) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dial),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func callIdentify(t *testing.T, conn *grpc.ClientConn, md metadata.MD) *testMsg {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if md != nil {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	out := new(testMsg)
	if err := conn.Invoke(ctx, "/authz.Test/Identify", &testMsg{}, out); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	return out
}

func sortedScopes(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestIdentifyCertMode(t *testing.T) {
	ca := newTestCA(t)

	grants := map[string]authz.Grant{
		"granted-multi": {
			Orgs:   []string{"orgA", "orgB"},
			Scopes: []string{"cred:read", "cred:write"},
		},
		"granted-single": {
			Orgs:   []string{"orgA"},
			Scopes: []string{"cred:read"},
		},
	}
	proxies := map[string]bool{"proxy": true}
	cfg := authz.Config{Mode: "cert", Grants: grants, TrustedProxies: proxies}

	dial, stop := startMTLSServer(t, ca, cfg)
	defer stop()

	certGrantedMulti := ca.leaf(t, "granted-multi", false)
	certGrantedSingle := ca.leaf(t, "granted-single", false)
	certUnknown := ca.leaf(t, "totally-unknown", false)
	certProxy := ca.leaf(t, "proxy", false)

	t.Run("granted, no metadata, defaults from grant", func(t *testing.T) {
		conn := dialMTLS(t, ca, dial, certGrantedSingle)
		out := callIdentify(t, conn, nil)
		if out.Err != "" {
			t.Fatalf("unexpected error: %s", out.Err)
		}
		if out.Sub != "granted-single" || out.Org != "orgA" {
			t.Fatalf("unexpected claims: %#v", out)
		}
		if !reflect.DeepEqual(out.Scopes, []string{"cred:read"}) {
			t.Fatalf("unexpected scopes: %#v", out.Scopes)
		}
	})

	t.Run("granted, matching metadata", func(t *testing.T) {
		conn := dialMTLS(t, ca, dial, certGrantedMulti)
		md := metadata.Pairs("cwb-subject", "granted-multi", "cwb-org", "orgB", "cwb-scopes", "cred:read")
		out := callIdentify(t, conn, md)
		if out.Err != "" {
			t.Fatalf("unexpected error: %s", out.Err)
		}
		if out.Sub != "granted-multi" || out.Org != "orgB" {
			t.Fatalf("unexpected claims: %#v", out)
		}
		if !reflect.DeepEqual(out.Scopes, []string{"cred:read"}) {
			t.Fatalf("unexpected scopes: %#v", out.Scopes)
		}
	})

	t.Run("multi-org grant without cwb-org is ambiguous", func(t *testing.T) {
		conn := dialMTLS(t, ca, dial, certGrantedMulti)
		out := callIdentify(t, conn, nil)
		if out.Err != "ErrNoIdentity" {
			t.Fatalf("got %q, want ErrNoIdentity", out.Err)
		}
	})

	t.Run("unknown CN", func(t *testing.T) {
		conn := dialMTLS(t, ca, dial, certUnknown)
		out := callIdentify(t, conn, nil)
		if out.Err != "ErrUnknownIdentity" {
			t.Fatalf("got %q, want ErrUnknownIdentity", out.Err)
		}
	})

	t.Run("subject mismatch", func(t *testing.T) {
		conn := dialMTLS(t, ca, dial, certGrantedSingle)
		md := metadata.Pairs("cwb-subject", "someone-else")
		out := callIdentify(t, conn, md)
		if out.Err != "ErrMismatch" {
			t.Fatalf("got %q, want ErrMismatch", out.Err)
		}
	})

	t.Run("org not in grant", func(t *testing.T) {
		conn := dialMTLS(t, ca, dial, certGrantedMulti)
		md := metadata.Pairs("cwb-org", "orgC")
		out := callIdentify(t, conn, md)
		if out.Err != "ErrMismatch" {
			t.Fatalf("got %q, want ErrMismatch", out.Err)
		}
	})

	t.Run("scope escalation attempt", func(t *testing.T) {
		conn := dialMTLS(t, ca, dial, certGrantedSingle)
		md := metadata.Pairs("cwb-scopes", "cred:read cred:delete-everything")
		out := callIdentify(t, conn, md)
		if out.Err != "ErrMismatch" {
			t.Fatalf("got %q, want ErrMismatch", out.Err)
		}
	})

	t.Run("trusted proxy honored with arbitrary metadata", func(t *testing.T) {
		conn := dialMTLS(t, ca, dial, certProxy)
		md := metadata.Pairs("cwb-subject", "arbitrary-user", "cwb-org", "arbitrary-org", "cwb-scopes", "b a")
		out := callIdentify(t, conn, md)
		if out.Err != "" {
			t.Fatalf("unexpected error: %s", out.Err)
		}
		if out.Sub != "arbitrary-user" || out.Org != "arbitrary-org" {
			t.Fatalf("unexpected claims: %#v", out)
		}
		if !reflect.DeepEqual(sortedScopes(out.Scopes), []string{"a", "b"}) {
			t.Fatalf("unexpected scopes: %#v", out.Scopes)
		}
	})
}

func TestIdentifyCertModeNoPeerCert(t *testing.T) {
	cfg := authz.Config{Mode: "cert"}
	dial, stop := startPlaintextServer(t, cfg)
	defer stop()

	conn := dialPlaintext(t, dial)
	out := callIdentify(t, conn, nil)
	if out.Err != "ErrNoPeerCert" {
		t.Fatalf("got %q, want ErrNoPeerCert", out.Err)
	}
}
