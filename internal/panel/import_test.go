package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

// postImport 以带鉴权的 POST 请求调用导入端点，返回响应 recorder。
func postImport(t *testing.T, p *Panel, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/panel/api/accounts/import", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

// writeSrc 在 srcDir 写一个 codebuddy 源凭证文件，返回文件名。
func writeSrc(t *testing.T, srcDir, name, raw string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(srcDir, name), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

const validSrc = `{"bearer_token":"at-1","refresh_token":"rt-1","user_id":"13372319277",
"uid":"13372319277","created_at":1787206715,"expires_in":5183954,"enabled":true,
"domain":"www.codebuddy.cn"}`

func decodeImport(t *testing.T, rec *httptest.ResponseRecorder) importResponse {
	t.Helper()
	var resp importResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%s", err, rec.Body.String())
	}
	return resp
}

func findResult(resp importResponse, file string) (importResult, bool) {
	for _, r := range resp.Results {
		if r.File == file {
			return r, true
		}
	}
	return importResult{}, false
}

func TestImportAccounts(t *testing.T) {
	srcDir := t.TempDir()
	authDir := t.TempDir()
	writeSrc(t, srcDir, "codebuddy_1001.json", validSrc)
	// enabled=false：跳过
	writeSrc(t, srcDir, "codebuddy_1002.json",
		`{"bearer_token":"at","refresh_token":"rt","uid":"1002","enabled":false,"domain":"www.codebuddy.cn"}`)
	// 缺 token：失败
	writeSrc(t, srcDir, "codebuddy_1003.json",
		`{"uid":"1003","enabled":true,"domain":"www.codebuddy.cn"}`)
	// uid 非法字符：失败（防路径穿越）
	writeSrc(t, srcDir, "codebuddy_1004.json",
		`{"bearer_token":"at","refresh_token":"rt","uid":"../../evil","enabled":true,"domain":"www.codebuddy.cn"}`)
	// 非 JSON：失败
	writeSrc(t, srcDir, "codebuddy_1005.json", `not-json`)
	// 不匹配 glob 的文件：忽略
	writeSrc(t, srcDir, "other_1006.json", `{}`)

	p := New(Config{Version: "test", APIKey: "test-key", AuthDir: authDir, Pool: pool.New("")})
	rec := postImport(t, p, `{"dir":"`+srcDir+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeImport(t, rec)
	if resp.Total != 5 || resp.Imported != 1 || resp.Skipped != 1 || resp.Failed != 3 {
		t.Fatalf("counts=%+v", resp)
	}
	if r, _ := findResult(resp, "codebuddy_1001.json"); r.Action != "imported" || r.UID != "13372319277" {
		t.Fatalf("1001: %+v", r)
	}
	if r, _ := findResult(resp, "codebuddy_1002.json"); r.Action != "skipped" {
		t.Fatalf("1002: %+v", r)
	}
	if r, _ := findResult(resp, "codebuddy_1003.json"); r.Action != "failed" {
		t.Fatalf("1003: %+v", r)
	}
	if r, _ := findResult(resp, "codebuddy_1004.json"); r.Action != "failed" {
		t.Fatalf("1004: %+v", r)
	}
	if r, _ := findResult(resp, "codebuddy_1005.json"); r.Action != "failed" {
		t.Fatalf("1005: %+v", r)
	}

	// 落盘文件为嵌套形，auth.Parse 可解析、realm=cn、过期时间 = created_at+expires_in。
	raw, err := os.ReadFile(filepath.Join(authDir, "workbuddy-13372319277.json"))
	if err != nil {
		t.Fatalf("dst missing: %v", err)
	}
	a, err := auth.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.AccessToken != "at-1" || a.RefreshToken != "rt-1" || a.Realm() != "cn" {
		t.Fatalf("auth=%+v realm=%s", a, a.Realm())
	}
	if a.ExpiresAt != 1787206715+5183954 {
		t.Fatalf("expiresAt=%d", a.ExpiresAt)
	}
	// 热加载进池
	if st, ok := p.cfg.Pool.Status("13372319277"); !ok || st.Disabled {
		t.Fatalf("pool status=%+v ok=%v", st, ok)
	}
}

func TestImportAccountsIdempotence(t *testing.T) {
	srcDir := t.TempDir()
	authDir := t.TempDir()
	writeSrc(t, srcDir, "codebuddy_2001.json", validSrc)

	p := New(Config{Version: "test", APIKey: "test-key", AuthDir: authDir, Pool: pool.New("")})

	// 首次导入成功。
	rec := postImport(t, p, `{"dir":"`+srcDir+`"}`)
	resp := decodeImport(t, rec)
	if resp.Imported != 1 {
		t.Fatalf("first import: %+v", resp)
	}

	// 重复导入：目标文件已存在 → skipped（幂等，不覆盖）。
	rec = postImport(t, p, `{"dir":"`+srcDir+`"}`)
	resp = decodeImport(t, rec)
	if resp.Imported != 0 || resp.Skipped != 1 {
		t.Fatalf("re-import: %+v", resp)
	}
	// 原文件未被改写（token 保持原值）。
	raw, _ := os.ReadFile(filepath.Join(authDir, "workbuddy-13372319277.json"))
	a, _ := auth.Parse(raw)
	if a.AccessToken != "at-1" {
		t.Fatalf("token overwritten: %s", a.AccessToken)
	}
}

func TestImportAccountsBadDir(t *testing.T) {
	p := New(Config{Version: "test", APIKey: "test-key", AuthDir: t.TempDir(), Pool: pool.New("")})
	rec := postImport(t, p, `{"dir":"/nonexistent/dir/xyz"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
}

// auths 目录不存在时自动创建（新部署首次导入的真实场景）。
func TestImportAccountsCreatesAuthDir(t *testing.T) {
	srcDir := t.TempDir()
	authDir := filepath.Join(t.TempDir(), "nested", "auths")
	writeSrc(t, srcDir, "codebuddy_3001.json", validSrc)

	p := New(Config{Version: "test", APIKey: "test-key", AuthDir: authDir, Pool: pool.New("")})
	rec := postImport(t, p, `{"dir":"`+srcDir+`"}`)
	resp := decodeImport(t, rec)
	if resp.Imported != 1 {
		t.Fatalf("import: %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(authDir, "workbuddy-13372319277.json")); err != nil {
		t.Fatalf("dst: %v", err)
	}
}

func TestImportAccountsAuthRequired(t *testing.T) {
	p := New(Config{Version: "test", APIKey: "test-key", AuthDir: t.TempDir(), Pool: pool.New("")})
	req := httptest.NewRequest("POST", "/panel/api/accounts/import", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
}
