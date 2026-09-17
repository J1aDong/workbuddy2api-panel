package panel

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
	"github.com/linguo2625469/workbuddy2api-panel/internal/pool"
)

// postImport 以带鉴权的 multipart POST 调用导入端点；files 为文件名 → 内容。
func postImport(t *testing.T, p *Panel, files map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for name, content := range files {
		fw, err := mw.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(fw, bytes.NewReader([]byte(content))); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/panel/api/accounts/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer test-key")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
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
	authDir := t.TempDir()
	p := New(Config{Version: "test", APIKey: "test-key", AuthDir: authDir, Pool: pool.New("")})

	files := map[string]string{
		"codebuddy_1001.json": validSrc,
		// enabled=false：跳过
		"codebuddy_1002.json": `{"bearer_token":"at","refresh_token":"rt","uid":"1002","enabled":false,"domain":"www.codebuddy.cn"}`,
		// 缺 token：失败
		"codebuddy_1003.json": `{"uid":"1003","enabled":true,"domain":"www.codebuddy.cn"}`,
		// uid 非法字符：失败（防路径穿越）
		"codebuddy_1004.json": `{"bearer_token":"at","refresh_token":"rt","uid":"../../evil","enabled":true,"domain":"www.codebuddy.cn"}`,
		// 非 JSON：失败
		"codebuddy_1005.json": `not-json`,
	}
	rec := postImport(t, p, files)
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
	// 路径穿越的 uid 没有落出 auths 目录。
	if _, err := os.Stat(filepath.Join(authDir, "workbuddy-..")); !os.IsNotExist(err) {
		t.Fatalf("traversal file exists: %v", err)
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

	// 重复导入：同 uid 已存在 → skipped（幂等，不覆盖）。
	rec = postImport(t, p, map[string]string{"codebuddy_1001.json": validSrc})
	resp = decodeImport(t, rec)
	if resp.Imported != 0 || resp.Skipped != 1 {
		t.Fatalf("re-import: %+v", resp)
	}
	raw, _ = os.ReadFile(filepath.Join(authDir, "workbuddy-13372319277.json"))
	a, _ = auth.Parse(raw)
	if a.AccessToken != "at-1" {
		t.Fatalf("token overwritten: %s", a.AccessToken)
	}
}

// auths 目录不存在时自动创建（新部署首次导入的真实场景）。
func TestImportAccountsCreatesAuthDir(t *testing.T) {
	srcDir := t.TempDir()
	authDir := filepath.Join(t.TempDir(), "nested", "auths")
	_ = srcDir
	p := New(Config{Version: "test", APIKey: "test-key", AuthDir: authDir, Pool: pool.New("")})
	rec := postImport(t, p, map[string]string{"codebuddy_3001.json": validSrc})
	resp := decodeImport(t, rec)
	if resp.Imported != 1 {
		t.Fatalf("import: %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(authDir, "workbuddy-13372319277.json")); err != nil {
		t.Fatalf("dst: %v", err)
	}
}

func TestImportAccountsNoFiles(t *testing.T) {
	p := New(Config{Version: "test", APIKey: "test-key", AuthDir: t.TempDir(), Pool: pool.New("")})
	rec := postImport(t, p, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	// 空 multipart（无 files 字段）与 JSON body（非 multipart）都报 400。
	req := httptest.NewRequest("POST", "/panel/api/accounts/import", bytes.NewReader([]byte(`{"dir":"/x"}`)))
	req.Header.Set("Authorization", "Bearer test-key")
	rec2 := httptest.NewRecorder()
	p.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("json body: code=%d", rec2.Code)
	}
}

func TestImportAccountsAuthRequired(t *testing.T) {
	p := New(Config{Version: "test", APIKey: "test-key", AuthDir: t.TempDir(), Pool: pool.New("")})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("files", "a.json")
	_, _ = fw.Write([]byte(validSrc))
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/panel/api/accounts/import", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rec.Code)
	}
}
