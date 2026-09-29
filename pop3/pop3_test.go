package pop3

import (
	"testing"
)

func TestPluginManifest(t *testing.T) {
	p := &Plugin{}
	manifest := p.Manifest()

	if manifest.Name != "pop3" {
		t.Fatalf("expected plugin name 'pop3', got: %s", manifest.Name)
	}

	if len(manifest.Protocols) == 0 || manifest.Protocols[0] != "pop3" {
		t.Fatalf("expected protocol 'pop3', got: %v", manifest.Protocols)
	}
}

func TestPluginSelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
}
