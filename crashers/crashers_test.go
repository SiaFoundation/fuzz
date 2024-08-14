package crashers

import (
	"encoding/json"
	"os"
	"testing"

	"go.sia.tech/fuzz/randgen"
)

func loadCrasher(t *testing.T, path string) (c randgen.Crasher) {
	js, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	} else if err := json.Unmarshal(js, &c); err != nil {
		t.Fatal(err)
	}
	return
}

func TestCoreutils_fee4ef5a(t *testing.T) {
	c := loadCrasher(t, "coreutils-fee4ef5a.json")

	cm := c.MemChainManager()
	if err := cm.AddBlocks(c.Blocks[:2]); err != nil {
		t.Fatal(err)
	}
	if err := cm.AddBlocks(c.Blocks[2:]); err != nil {
		t.Fatal(err)
	}
}
