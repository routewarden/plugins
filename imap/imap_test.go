package imap

import (
	"testing"
)

func TestPluginManifest(t *testing.T) {
	p := &Plugin{}
	manifest := p.Manifest()

	if manifest.Name != "imap" {
		t.Fatalf("expected plugin name 'imap', got: %s", manifest.Name)
	}

	if len(manifest.Protocols) == 0 || manifest.Protocols[0] != "imap" {
		t.Fatalf("expected protocol 'imap', got: %v", manifest.Protocols)
	}
}

func TestPluginSelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest failed: %v", err)
	}
}
