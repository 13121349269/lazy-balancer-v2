package dnspod

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// staleCreateRemoveTransport 模拟 Present 阶段缓存陈旧的完整流程（AD-1）：
// Domain.List 恒返回 currentID；Record.Create/Record.Remove 对其他
// domain_id 报「域名ID错误」（code 6），对 currentID 正常创建/删除。
// 记录每次 Create/Remove 的 domain_id 与 Remove 的 {domain_id, record_id}。
type staleCreateRemoveTransport struct {
	mu        sync.Mutex
	currentID string
	records   map[string]string
	creates   []string
	removes   [][2]string
	nextID    int
}

func (transport *staleCreateRemoveTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	responseBody := `{"status":{"code":"1","message":"ok"}}`
	transport.mu.Lock()
	switch {
	case strings.HasSuffix(request.URL.Path, "Domain.List"):
		responseBody = fmt.Sprintf(`{"status":{"code":"1","message":"ok"},"domains":[{"id":%q,"name":"example.com"}],"info":{"domain_total":1}}`, transport.currentID)
	case strings.HasSuffix(request.URL.Path, "Record.Create"):
		domainID := params.Get("domain_id")
		transport.creates = append(transport.creates, domainID)
		if domainID != transport.currentID {
			responseBody = `{"status":{"code":"6","message":"域名ID错误"}}`
		} else {
			transport.nextID++
			recordID := strconv.Itoa(899 + transport.nextID)
			transport.records[recordID] = params.Get("value")
			responseBody = fmt.Sprintf(`{"status":{"code":"1","message":"ok"},"record":{"id":%q}}`, recordID)
		}
	case strings.HasSuffix(request.URL.Path, "Record.Remove"):
		removal := [2]string{params.Get("domain_id"), params.Get("record_id")}
		transport.removes = append(transport.removes, removal)
		if removal[0] != transport.currentID {
			responseBody = `{"status":{"code":"6","message":"域名ID错误"}}`
		} else {
			delete(transport.records, removal[1])
		}
	}
	transport.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(responseBody)),
		Request:    request,
	}, nil
}

// AD-1（第 70 轮审计）：Present 陈旧 domain_id 自愈重试成功后必须回写
// domainID=freshID（与 cleanUp deleteOne U5-1 回写对称）——否则 ownership
// 模式下 Add 失败的回滚删除打向陈旧 ID（对陈旧 ID 报域名不存在类错误，
// 回滚必败 → TXT 泄漏），FreshID 打才可能真正删掉刚创建的记录。
func TestProvider_Present_staleRetryRollsBackWithFreshDomainID(t *testing.T) {
	// Given：缓存陈旧 id，API 侧域名已重建为 42；ownership 落盘文件路径
	// 被目录占据（os.ReadFile 报错且非 ErrNotExist）使 Add 必败，触发回滚。
	seedDomainIDCache(t, "id,token", map[string]string{"example.com": "stale-1"})
	transport := &staleCreateRemoveTransport{currentID: "42", records: map[string]string{}}
	dataDir := t.TempDir()
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
	if err := os.Mkdir(filepath.Join(dataDir, "acme_dns_ownership.json"), 0755); err != nil {
		t.Fatalf("block ownership file: %v", err)
	}

	// When：Present 自愈重试成功后 ownership.Add 失败 → 回滚删除
	err = provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "this-task", 600)

	// Then：回滚删除必须打向 freshID 并真删（旧代码打陈旧 ID → 删除必败、TXT 泄漏）
	if err == nil {
		t.Fatal("want error（ownership.Add 必败）, got nil")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.removes) != 1 || transport.removes[0][0] != "42" {
		t.Fatalf("Record.Remove calls=%v, want [[42 <recordID>]]（回滚须用 freshID）", transport.removes)
	}
	if len(transport.records) != 0 {
		t.Fatalf("TXT 记录泄漏=%v（回滚删除未生效——打向了陈旧 domain_id）", transport.records)
	}
}

// AD-1 内存模式形状：陈旧 ID 自愈重试成功后 owned 键必须以 freshID 构键——
// 否则后续 CleanUp 以（重解析后的）freshID 构键查不到条目，静默零删除返回
// nil，TXT 残留而验证成功。
func TestProvider_Present_staleRetryKeysOwnedWithFreshDomainID(t *testing.T) {
	// Given：缓存陈旧 id，API 侧域名已重建为 42
	seedDomainIDCache(t, "id,token", map[string]string{"example.com": "stale-1"})
	transport := &staleCreateRemoveTransport{currentID: "42", records: map[string]string{}}
	provider := New("id,token")
	provider.client.Transport = transport
	if err := provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "this-task", 600); err != nil {
		t.Fatalf("present with stale cache: %v", err)
	}
	transport.mu.Lock()
	creates := append([]string(nil), transport.creates...)
	transport.mu.Unlock()
	if !reflect.DeepEqual(creates, []string{"stale-1", "42"}) {
		t.Fatalf("Record.Create domain_ids=%v, want [stale-1 42]（自愈重试形状前置校验）", creates)
	}

	// When：CleanUp（缓存已由 Present 重解析刷新为 42，键按 freshID 构造）
	err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com.")

	// Then：owned 键与 CleanUp 键一致——记录被真删
	if err != nil {
		t.Fatalf("clean up: %v", err)
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.removes) != 1 || transport.removes[0][0] != "42" {
		t.Fatalf("Record.Remove calls=%v, want [[42 <recordID>]]", transport.removes)
	}
	if len(transport.records) != 0 {
		t.Fatalf("TXT 记录残留=%v（owned 键仍打陈旧 domain_id → CleanUp 键不匹配零删除）", transport.records)
	}
}
