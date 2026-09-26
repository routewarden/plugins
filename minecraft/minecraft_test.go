package minecraft

import (
	"testing"
)

func TestMinecraftPlugin_SelfTest(t *testing.T) {
	p := &Plugin{}
	if err := p.SelfTest(); err != nil {
		t.Fatalf("minecraft SelfTest failed: %v", err)
	}
}
