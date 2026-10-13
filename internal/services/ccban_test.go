package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestCCBanReadConfig_defaultsAndClamp(t *testing.T) {
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mgr := &WafAutoBanManager{}
	cfg, err := mgr.readCCBanConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatalf("default enabled must be false, got true")
	}
	if cfg.Threshold != 10 || cfg.WindowMinutes != 10 || cfg.DurationHours != 1 {
		t.Fatalf("default config = %+v, want threshold=10 window=10 duration=1", cfg)
	}

	if _, err := db.DB.Exec(`UPDATE global_config SET cc_ban_enabled=1, cc_ban_threshold=0, cc_ban_window_minutes=0, cc_ban_duration_hours=-1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	cfg, err = mgr.readCCBanConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled {
		t.Fatalf("enabled not read")
	}
	if cfg.Threshold != 10 || cfg.WindowMinutes != 10 || cfg.DurationHours != 1 {
		t.Fatalf("clamped config = %+v, want threshold=10 window=10 duration=1", cfg)
	}
}

func TestCCBanScanLogFile_parses429WithinWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rule.log")
	now := time.Now().UTC()
	lines := []map[string]interface{}{
		{"ts": float64(now.Unix()), "status": 429, "request": map[string]interface{}{"remote_ip": "1.2.3.4"}},
		{"ts": float64(now.Unix()), "status": 200, "request": map[string]interface{}{"remote_ip": "5.6.7.8"}},
		{"ts": float64(now.Add(-2 * time.Hour).Unix()), "status": 429, "request": map[string]interface{}{"remote_ip": "9.9.9.9"}},
		{"ts": float64(now.Unix()), "status": 429, "request": map[string]interface{}{"remote_ip": "1.2.3.4"}},
	}
	var data []byte
	for _, l := range lines {
		b, _ := json.Marshal(l)
		data = append(data, b...)
		data = append(data, '\n')
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	counts, err := ccBanScanLogFile(path, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if counts["1.2.3.4"] != 2 {
		t.Fatalf("1.2.3.4 count = %d, want 2", counts["1.2.3.4"])
	}
	if _, ok := counts["5.6.7.8"]; ok {
		t.Fatalf("non-429 IP must not be counted")
	}
	if _, ok := counts["9.9.9.9"]; ok {
		t.Fatalf("out-of-window 429 must not be counted")
	}
}

func TestCCBanParseRemark(t *testing.T) {
	ts, ok := ccBanParseRemark("cc_ban:1700000000")
	if !ok || ts.Unix() != 1700000000 {
		t.Fatalf("cc_ban remark parse failed: %v %v", ts, ok)
	}
	if _, ok := ccBanParseRemark("auto_ban:1700000000"); ok {
		t.Fatalf("auto_ban remark must not parse as cc_ban")
	}
	if _, ok := ccBanParseRemark("garbage"); ok {
		t.Fatalf("garbage remark must not parse")
	}
}

func TestCCBanPruneExpired(t *testing.T) {
	now := time.Now().UTC()
	entries := []models.IPListEntry{
		{Value: "1.1.1.1", Remark: "cc_ban:1700000000"},
		{Value: "2.2.2.2", Remark: "auto_ban:1700000000"},
	}
	pruned, kept := ccBanPruneExpired(entries, now, time.Hour)
	if !pruned {
		t.Fatalf("expired cc_ban entry should be pruned")
	}
	if len(kept) != 1 || kept[0].Value != "2.2.2.2" {
		t.Fatalf("auto_ban entry must be preserved, kept=%+v", kept)
	}
}

func TestCCBanCandidates_aggregatesAcrossRules(t *testing.T) {
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,log_enabled) VALUES ('cc_a','a','http',8080,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,log_enabled) VALUES ('cc_b','b','http',8081,1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,log_enabled) VALUES ('cc_off','off','http',8082,1,0)`); err != nil {
		t.Fatal(err)
	}

	oldDir := ccBanLogDir
	ccBanLogDir = t.TempDir()
	t.Cleanup(func() { ccBanLogDir = oldDir })

	now := time.Now().UTC()
	write429 := func(id, ip string, n int) {
		path := ccBanLogPath(id)
		var data []byte
		for i := 0; i < n; i++ {
			b, _ := json.Marshal(map[string]interface{}{"ts": float64(now.Unix()), "status": 429, "request": map[string]interface{}{"remote_ip": ip}})
			data = append(data, b...)
			data = append(data, '\n')
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	write429("cc_a", "10.0.0.1", 3)
	write429("cc_b", "10.0.0.1", 7)
	write429("cc_off", "10.0.0.1", 100)

	mgr := &WafAutoBanManager{}
	candidates, err := mgr.ccBanCandidates(ccBanConfig{Enabled: true, Threshold: 10, WindowMinutes: 10}, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0] != "10.0.0.1" {
		t.Fatalf("candidates = %v, want [10.0.0.1]", candidates)
	}

	candidates, err = mgr.ccBanCandidates(ccBanConfig{Enabled: true, Threshold: 11, WindowMinutes: 10}, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("candidates under threshold = %v, want empty", candidates)
	}
}
