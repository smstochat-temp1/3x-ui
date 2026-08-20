package database

import (
	"path/filepath"
	"testing"
)

func TestDropPiaManagedTables(t *testing.T) {
	if err := InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseDB() })

	for _, name := range []string{"pia_profiles", "pia_egresses", "pia_bindings", "pia_catalog_snapshots"} {
		if err := GetDB().Exec("CREATE TABLE " + name + " (id integer)").Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := dropPiaManagedTables(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pia_profiles", "pia_egresses", "pia_bindings", "pia_catalog_snapshots"} {
		if GetDB().Migrator().HasTable(name) {
			t.Fatalf("expected %s to be dropped", name)
		}
	}
}
