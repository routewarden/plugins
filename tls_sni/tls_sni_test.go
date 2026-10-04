package tls_sni

import (
	"testing"
)

func TestTLSSNIPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("tls_sni SelfTest failed: %v", err)
	}
}

func TestTLSSNIPlugin_ManifestAndConfig(t *testing.T) {
	p := &Plugin{}
	m := p.Manifest()
	if m.Name != "tls_sni" {
		t.Errorf("expected tls_sni, got %s", m.Name)
	}

	cfg := map[string]any{
		"allowed_domains": []string{"*.example.com"},
		"blocked_domains": []string{"*.evil.com"},
	}
	if err := p.ValidateConfig(cfg); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(cfg)
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}

func TestMatchDomain_TrailingDots(t *testing.T) {
	if !matchDomain("example.com.", "*.example.com") {
		t.Error("expected example.com. with trailing dot to match *.example.com")
	}
	if !matchDomain("sub.example.com.", "*.example.com.") {
		t.Error("expected sub.example.com. to match *.example.com.")
	}
	if !matchDomain("foo.bar.com", "foo.bar.com.") {
		t.Error("expected foo.bar.com to match foo.bar.com.")
	}
}

