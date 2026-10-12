package dnsprovider

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/dnsprovider/dnspod"
	"lazy-balancer-v2/internal/dnsprovider/tencent"
)

func TestNewProviderFromCredentials_infers_mode_from_credential_fields(t *testing.T) {
	// Given/When/Then: legacy rows migrated before the mode field existed
	// carry only the credential fields — infer instead of rejecting
	provider, err := NewProviderFromCredentials(`{"api_token":"123,abc"}`)
	if err != nil {
		t.Fatalf("infer dnspod from api_token: %v", err)
	}
	if _, ok := provider.(*dnspod.Provider); !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}

	provider, err = NewProviderFromCredentials(`{"secret_id":"id","secret_key":"key"}`)
	if err != nil {
		t.Fatalf("infer tencent from secret pair: %v", err)
	}
	if _, ok := provider.(*tencent.Provider); !ok {
		t.Fatalf("provider=%T, want *tencent.Provider", provider)
	}

	// Legacy UI form without auth_mode also infers dnspod from app_id/app_token
	provider, err = NewProviderFromCredentials(`{"app_id":"123","app_token":"abc"}`)
	if err != nil {
		t.Fatalf("infer dnspod from legacy app_id/app_token: %v", err)
	}
	if _, ok := provider.(*dnspod.Provider); !ok {
		t.Fatalf("provider=%T, want *dnspod.Provider", provider)
	}
}

func TestNewProviderFromCredentials_rejects_ambiguous_or_missing_credentials(t *testing.T) {
	// Given/When/Then: both credential families present is ambiguous
	if _, err := NewProviderFromCredentials(`{"api_token":"123,abc","secret_id":"id","secret_key":"key"}`); err == nil {
		t.Fatal("ambiguous credentials must be rejected")
	}
	// No credentials at all
	if _, err := NewProviderFromCredentials(`{}`); err == nil {
		t.Fatal("missing credentials must be rejected")
	}
	// Incomplete secret pair cannot select tencent and has no token either
	if _, err := NewProviderFromCredentials(`{"secret_id":"id"}`); err == nil {
		t.Fatal("incomplete secret pair must be rejected")
	}
}

func TestNewProviderFromCredentials_explicit_mode_still_wins(t *testing.T) {
	// Given/When: explicit mode with matching credentials
	provider, err := NewProviderFromCredentials(`{"mode":"tencent","secret_id":"id","secret_key":"key"}`)
	if err != nil {
		t.Fatalf("explicit mode: %v", err)
	}

	// Then
	if _, ok := provider.(*tencent.Provider); !ok {
		t.Fatalf("provider=%T, want *tencent.Provider", provider)
	}
}

// A-1（第 73 轮）：空 mode 无法推断时的错误文案必须可诊断分流——两类凭证
// 并存=歧义（需显式 mode 消歧），全缺/不完整=缺失（需补齐凭证）。原实现两者
// 同落 default 的「unsupported dns provider mode: 」（mode 为空），排障无法区分。
func TestNewProviderFromCredentials_emptyModeErrorDistinguishesAmbiguityFromMissing(t *testing.T) {
	_, ambiguousErr := NewProviderFromCredentials(`{"api_token":"123,abc","secret_id":"id","secret_key":"key"}`)
	if ambiguousErr == nil {
		t.Fatal("ambiguous credentials must be rejected")
	}
	_, missingErr := NewProviderFromCredentials(`{}`)
	if missingErr == nil {
		t.Fatal("missing credentials must be rejected")
	}
	if ambiguousErr.Error() == missingErr.Error() {
		t.Fatalf("歧义与缺失必须给出不同文案, both=%q", ambiguousErr.Error())
	}
	if !strings.Contains(ambiguousErr.Error(), "歧义") {
		t.Fatalf("歧义文案须含「歧义」, got %q", ambiguousErr.Error())
	}
	if !strings.Contains(missingErr.Error(), "缺失") {
		t.Fatalf("缺失文案须含「缺失」, got %q", missingErr.Error())
	}
	// 显式未知 mode 仍走原 unsupported 文案（非空 mode 不进歧义/缺失分流）。
	if _, err := NewProviderFromCredentials(`{"mode":"route53","api_token":"1,2"}`); err == nil ||
		!strings.Contains(err.Error(), "unsupported dns provider mode") {
		t.Fatalf("显式未知 mode 须保留原 unsupported 文案, got %v", err)
	}
}
