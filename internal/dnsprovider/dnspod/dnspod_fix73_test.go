package dnspod

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

// toggleRemoveFailTransport 让 Record.Remove 一律在 HTTP 层失败（其余委托基础
// transport）；failRemove 可切换，模拟删除恢复。
type toggleRemoveFailTransport struct {
	dnsPodRecordTransport
	failMu     sync.Mutex
	failRemove bool
}

func (transport *toggleRemoveFailTransport) setFailRemove(v bool) {
	transport.failMu.Lock()
	transport.failRemove = v
	transport.failMu.Unlock()
}

func (transport *toggleRemoveFailTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.failMu.Lock()
	fail := transport.failRemove
	transport.failMu.Unlock()
	if fail && strings.HasSuffix(request.URL.Path, "Record.Remove") {
		return nil, errors.New("simulated dnsapi outage")
	}
	return transport.dnsPodRecordTransport.RoundTrip(request)
}

// A-2（第 73 轮）：ownership.Add 失败且回滚删除亦失败时，TXT 已落 DNS 而
// store 无条目可追踪。修复=告警留痕 + 回填内存兜底表；后续 cleanUp 的
// ownership 分支排空兜底表并重试删除（否则该记录永久残留）。
func TestProvider_Present_ownershipAddAndRollbackFailureRefillsFallback(t *testing.T) {
	// Given：有效 ownership 文件（load 成功）但目录只读 → save 失败 →
	// ownership.Add 失败；同时 Record.Remove 失败 → 回滚删除亦失败。
	dataDir := t.TempDir()
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	if err := store.Add(ownership.Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.seed.example.com.", Value: "seed", RecordID: "999"}); err != nil {
		t.Fatalf("seed ownership file: %v", err)
	}
	transport := &toggleRemoveFailTransport{dnsPodRecordTransport: dnsPodRecordTransport{records: map[string]string{}}, failRemove: true}
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
	if err := os.Chmod(dataDir, 0o555); err != nil {
		t.Fatalf("make ownership dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o755) })

	// When
	err = provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	// Then：双失败上报 + 记录回填内存兜底表
	if err == nil {
		t.Fatal("ownership.Add 失败 + 回滚删除失败必须上报，不得静默")
	}
	provider.mu.Lock()
	entries := append([]ownedRecord(nil), provider.owned["1|_acme-challenge"]...)
	provider.mu.Unlock()
	if len(entries) != 1 || entries[0].recordID != "200" {
		t.Fatalf("owned fallback=%+v, want 孤儿记录 200 回填", entries)
	}

	// When：存储与删除均恢复 → cleanUp 排空兜底表并重试删除
	if err := os.Chmod(dataDir, 0o755); err != nil {
		t.Fatalf("restore ownership dir: %v", err)
	}
	transport.setFailRemove(false)
	if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("clean up after recovery: %v", err)
	}

	// Then：孤儿记录被删除且兜底表清空
	transport.mu.Lock()
	_, alive := transport.records["200"]
	transport.mu.Unlock()
	if alive {
		t.Fatal("兜底条目必须在 cleanUp 中被删除（无追踪窗口未收口）")
	}
	provider.mu.Lock()
	left := provider.owned["1|_acme-challenge"]
	provider.mu.Unlock()
	if len(left) != 0 {
		t.Fatalf("排空成功后兜底表须清空, got %+v", left)
	}
}
