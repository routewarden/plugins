package ssh

import (
	"testing"
)

func TestPluginManifest(t *testing.T) {
	p := &Plugin{}
	manifest := p.Manifest()

	if manifest.Name != "ssh" {
		t.Fatalf("expected plugin name 'ssh', got: %s", manifest.Name)
	}

	if len(manifest.Protocols) == 0 || manifest.Protocols[0] != "ssh" {
		t.Fatalf("expected protocol 'ssh', got: %v", manifest.Protocols)
	}
}

func TestPluginSelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
}
