// import.go 批量导入外部凭证目录的账号（面板「添加账号」弹窗内的导入入口）。
//
// 来源：CodeBuddy CLI 网关（~/.codebuddy2api/credentials/codebuddy_<uid>.json）的
// 扁平格式凭证，转换为本项目 auths/ 目录的嵌套格式（auth.Parse 双形态中的嵌套形），
// 复用登录路径的热加载语义（SaveAtomic 落盘 → pool.Add → Revive）免重启进池。
//
// 导入即信任：与手工放置凭证文件等效（面板本身受 Bearer 鉴权保护），字段校验
// 只负责防脏数据与路径穿越，不做上游连通性预检（导入后由保活/余额刷新自然暴露）。
package panel

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// codebuddyCred 源凭证的关心字段（扁平形；usage_raw 等大对象不解析）。
type codebuddyCred struct {
	BearerToken  string `json:"bearer_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	UID          string `json:"uid"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresIn    int64  `json:"expires_in"`
	Enabled      *bool  `json:"enabled"`
	Domain       string `json:"domain"`
}

// importResult 单文件导入结果；明细随响应返回，前端逐行展示。
type importResult struct {
	File   string `json:"file"`
	UID    string `json:"uid,omitempty"`
	Action string `json:"action"` // imported / skipped / failed
	Reason string `json:"reason,omitempty"`
}

// importRequest/importResponse 端点入参与返回。
type importRequest struct {
	Dir string `json:"dir"`
}

type importResponse struct {
	Ok       bool           `json:"ok"`
	Dir      string         `json:"dir"`
	Total    int            `json:"total"`
	Imported int            `json:"imported"`
	Skipped  int            `json:"skipped"`
	Failed   int            `json:"failed"`
	Results  []importResult `json:"results"`
}

// importAccounts 批量导入：扫描 dir 下 codebuddy_*.json → 转换 → 落盘 → 热加载。
// 同步执行（文件数有界、纯本地 IO + 池内存操作），不用异步队列。
func (p *Panel) importAccounts(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 1<<15)).Decode(&req)
	}
	dir := strings.TrimSpace(req.Dir)
	if dir == "" {
		dir = defaultImportDir()
	}
	// 展开 ~（macOS/Linux；Windows 由 os.UserHomeDir 返回 %USERPROFILE%，同样适用）。
	if strings.HasPrefix(dir, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, dir[1:])
		}
	}
	dir = filepath.Clean(dir)

	// 目录必须存在，否则明确报错（前端展示给用户）。
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		writeErr(w, http.StatusBadRequest, "目录不存在或不可读: "+dir)
		return
	}

	files, err := filepath.Glob(filepath.Join(dir, "codebuddy_*.json"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scan failed: "+err.Error())
		return
	}
	resp := importResponse{Ok: true, Dir: dir, Total: len(files)}
	// 新部署 auths/ 目录可能尚不存在（登录路径会建，导入路径自建），缺失时 SaveAtomic 写 tmp 失败。
	if err := os.MkdirAll(p.cfg.AuthDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "mkdir auth dir: "+err.Error())
		return
	}
	for _, f := range files {
		res := p.importOne(f)
		switch res.Action {
		case "imported":
			resp.Imported++
		case "skipped":
			resp.Skipped++
		default:
			resp.Failed++
		}
		resp.Results = append(resp.Results, res)
	}
	log.Printf("panel: 批量导入 dir=%s total=%d imported=%d skipped=%d failed=%d",
		dir, resp.Total, resp.Imported, resp.Skipped, resp.Failed)
	writeJSON(w, http.StatusOK, resp)
}

// importOne 转换并导入单个凭证文件，返回逐文件结果。
//   - enabled=false → skipped（用户主动停用的号不进池）
//   - 目标文件已存在 → skipped（不覆盖手工/既有凭证；先删后导可重导）
//   - 缺 bearer_token/refresh_token 或 uid 非法 → failed（脏数据，需人工处理）
func (p *Panel) importOne(src string) importResult {
	base := filepath.Base(src)
	res := importResult{File: base}
	raw, err := os.ReadFile(src)
	if err != nil {
		res.Action = "failed"
		res.Reason = "read: " + err.Error()
		return res
	}
	var c codebuddyCred
	if err := json.Unmarshal(raw, &c); err != nil {
		res.Action = "failed"
		res.Reason = "parse: " + err.Error()
		return res
	}
	if c.Enabled != nil && !*c.Enabled {
		res.Action = "skipped"
		res.Reason = "enabled=false"
		return res
	}
	uid := strings.TrimSpace(c.UID)
	if uid == "" {
		uid = strings.TrimSpace(c.UserID)
	}
	if uid == "" || !validUID(uid) {
		res.Action = "failed"
		res.Reason = "uid 缺失或含非法字符"
		return res
	}
	if strings.TrimSpace(c.BearerToken) == "" || strings.TrimSpace(c.RefreshToken) == "" {
		res.Action = "failed"
		res.Reason = "缺 bearer_token / refresh_token"
		return res
	}
	res.UID = uid

	dst := filepath.Join(p.cfg.AuthDir, fmt.Sprintf("workbuddy-%s.json", uid))
	if _, err := os.Stat(dst); err == nil {
		res.Action = "skipped"
		res.Reason = "已存在同名凭证（不覆盖）"
		return res
	}

	a := &auth.Auth{
		AccessToken:  strings.TrimSpace(c.BearerToken),
		RefreshToken: strings.TrimSpace(c.RefreshToken),
		ExpiresAt:    resolveImportExpiry(c),
		// domain 原样保留（token 刷新响应会再回填）；realm 按 domain 归一，
		// www.codebuddy.cn → cn，www.workbuddy.ai → global。
		Domain:   strings.TrimSpace(c.Domain),
		UID:      uid,
		FilePath: dst,
	}
	a.BackfillRealm()
	if err := a.SaveAtomic(); err != nil {
		res.Action = "failed"
		res.Reason = "save: " + err.Error()
		return res
	}
	p.cfg.Pool.Add(a)
	p.cfg.Pool.Revive(uid) // 与登录路径同口径：清旧禁用/冷却/熔断，人工恢复语义
	res.Action = "imported"
	log.Printf("panel: 导入账号 uid=%s src=%s", uid, base)
	return res
}

// resolveImportExpiry 计算导入凭证的过期时间：expires_in 相对 created_at 起算
// （codebuddy CLI 的口径）；缺 created_at 按当前时间兜底。expires_in 缺失/非法 → 0
// （NeedsRefresh 视为需要刷新，保活任务会自然补一次刷新）。
func resolveImportExpiry(c codebuddyCred) int64 {
	if c.ExpiresIn <= 0 {
		return 0
	}
	base := c.CreatedAt
	if base <= 0 {
		base = time.Now().Unix()
	}
	return base + c.ExpiresIn
}

// defaultImportDir 默认扫描目录（跨平台 home 下 .codebuddy2api/credentials）。
func defaultImportDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".codebuddy2api", "credentials")
}
