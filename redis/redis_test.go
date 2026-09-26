package redis

import (
	"testing"
)

func TestRedisPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("redis SelfTest failed: %v", err)
	}
}

func TestRedisPlugin_ManifestAndConfig(t *testing.T) {
	p := &Plugin{}
	m := p.Manifest()
	if m.Name != "redis" {
		t.Errorf("expected redis, got %s", m.Name)
	}

	if err := p.ValidateConfig(map[string]any{"blocked_commands": []string{"FLUSHALL", "CONFIG"}}); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	insp, err := p.CreateInspector(map[string]any{"blocked_commands": []any{"FLUSHALL"}})
	if err != nil || insp == nil {
		t.Fatalf("failed creating inspector: %v", err)
	}
}
