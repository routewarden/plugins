package smtp

import (
	"testing"
)

func TestPluginManifest(t *testing.T) {
	p := &Plugin{}
	manifest := p.Manifest()

	if manifest.Name != "smtp" {
		t.Fatalf("expected plugin name 'smtp', got: %s", manifest.Name)
	}

	if len(manifest.Protocols) == 0 || manifest.Protocols[0] != "smtp" {
		t.Fatalf("expected protocol 'smtp', got: %v", manifest.Protocols)
	}
}

func TestPluginSelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
}
