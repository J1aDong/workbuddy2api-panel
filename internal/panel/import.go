// import.go 批量导入凭证文件（面板「添加账号」弹窗内的导入入口）。
//
// 来源：CodeBuddy CLI 网关导出的扁平凭证文件（codebuddy_<uid>.json：bearer_token/
// refresh_token / uid / domain…），经浏览器文件选择器 multipart 多文件上传到面板，
// 转换为 auths/ 的嵌套格式（auth.Parse 双形态中的嵌套形），复用登录路径的热加载
// 语义（SaveAtomic 落盘 → pool.Add → Revive）免重启进池。
//
// 走上传而非服务端路径扫描：网关常部署在 Docker / 远端，宿主机上的凭证目录在
// 容器内不可见；把文件内容传进来，部署位置不再约束导入。
//
// 导入即信任：与手工放置凭证文件等效（面板本身受 Bearer 鉴权保护），字段校验
// 只负责防脏数据与路径穿越，不做上游连通性预检（导入后由保活/余额刷新自然暴露）。
package panel

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/linguo2625469/workbuddy2api-panel/internal/auth"
)

// 导入上限：单文件 4MB（真实凭证含 usage_raw 约 100KB，余量充足）、单次 200 个、
// 总体积 128MB——防异常上传拖垮面板，同时远超正常使用量。
const (
	importMaxFileBytes   int64 = 4 << 20
	importMaxFiles             = 200
	importMaxTotalBytes int64 = 128 << 20
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

// importResponse 端点返回。
type importResponse struct {
	Ok       bool           `json:"ok"`
	Total    int            `json:"total"`
	Imported int            `json:"imported"`
	Skipped  int            `json:"skipped"`
	Failed   int            `json:"failed"`
	Results  []importResult `json:"results"`
}

// importAccounts 批量导入：multipart 字段 files（可重复）→ 逐个解析转换 → 落盘 → 热加载。
// 同步执行（文件数有上限、纯本地 IO + 池内存操作），不用异步队列。
func (p *Panel) importAccounts(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, importMaxTotalBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "上传解析失败（multipart 格式错误或超过大小上限）: "+err.Error())
		return
	}
	defer func() { _ = r.MultipartForm.RemoveAll() }() // 超过内存阈值的部分落了 tmp 文件，统一清理
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		writeErr(w, http.StatusBadRequest, "未上传任何文件（multipart 文件字段名须为 files）")
		return
	}
	if len(files) > importMaxFiles {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("一次最多导入 %d 个文件，收到 %d 个", importMaxFiles, len(files)))
		return
	}
	// 新部署 auths/ 目录可能尚不存在（登录路径会建，导入路径自建），缺失时 SaveAtomic 写 tmp 失败。
	if err := os.MkdirAll(p.cfg.AuthDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "mkdir auth dir: "+err.Error())
		return
	}
	resp := importResponse{Ok: true, Total: len(files)}
	for _, fh := range files {
		res := p.importOne(fh)
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
	log.Printf("panel: 批量导入 total=%d imported=%d skipped=%d failed=%d",
		resp.Total, resp.Imported, resp.Skipped, resp.Failed)
	writeJSON(w, http.StatusOK, resp)
}

// importOne 解析并导入单个上传文件，返回逐文件结果。
//   - enabled=false → skipped（用户主动停用的号不进池）
//   - 同 uid 目标凭证已存在 → skipped（不覆盖既有凭证；先移除可重导）
//   - 非 JSON / 缺 bearer_token、refresh_token / uid 非法 → failed（脏数据，需人工处理）
func (p *Panel) importOne(fh *multipart.FileHeader) importResult {
	// 文件名仅作展示；Base 防客户端传带路径的名字。
	name := filepath.Base(fh.Filename)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "unnamed.json"
	}
	res := importResult{File: name}
	if fh.Size > importMaxFileBytes {
		res.Action = "failed"
		res.Reason = fmt.Sprintf("文件超过 %dMB 上限", importMaxFileBytes>>20)
		return res
	}
	f, err := fh.Open()
	if err != nil {
		res.Action = "failed"
		res.Reason = "open: " + err.Error()
		return res
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, importMaxFileBytes+1))
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
	log.Printf("panel: 导入账号 uid=%s src=%s", uid, name)
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
