// Package capture 实现 SEC-003/P1-04C 的 MEMORY-ONLY 诊断正文捕获。
//
// 设计底线（ADR-007）：
//   - 正文只存在于本进程内存：不进 SQLite、不进 YAML、不进日志文件/stdout、
//     不进 WebSocket、不进普通 Dashboard HTML
//   - 显式 opt-in（config request_body_capture.enabled），硬过期 ≤24h
//   - 到期自动 disable + 清空（真实 timer，不依赖"下一次请求才发现过期"）
//   - bounded：max_bytes 截断、max_entries 淘汰最旧
//   - eviction/清空时对字节切片做 best-effort 置零
//   - 所有方法对 nil receiver 安全（未接线 = 捕获关闭）
package capture

import (
	"sync"
	"time"
)

// Entry: 单条捕获记录（Get 返回 Body 的副本，防止调用方修改内部状态）。
type Entry struct {
	RequestID  string
	Body       []byte
	CapturedAt time.Time
	Truncated  bool
}

// Store: thread-safe bounded memory store。
type Store struct {
	mu         sync.Mutex
	enabled    bool
	expiresAt  time.Time
	maxBytes   int
	maxEntries int
	entries    map[string]*Entry
	order      []string // FIFO 淘汰序
	now        func() time.Time
}

// NewStore: 构造捕获存储。enabled=false 时为惰性空存储（Capture/Get 均 no-op）。
// expiresAt 已过 → 立即 disable。
func NewStore(enabled bool, expiresAt time.Time, maxBytes, maxEntries int) *Store {
	s := &Store{
		enabled:    enabled,
		expiresAt:  expiresAt,
		maxBytes:   maxBytes,
		maxEntries: maxEntries,
		entries:    make(map[string]*Entry),
		now:        time.Now,
	}
	if enabled {
		if d := time.Until(expiresAt); d > 0 {
			// 真正的到时清理（不依赖下一次请求触发）
			time.AfterFunc(d, s.disableAndClear)
		} else {
			s.enabled = false
		}
	}
	return s
}

// Capture: 记录一次请求正文（仅已认证 LLM API 请求允许调用）。
// 捕获前截断至 maxBytes；容量满时淘汰最旧；过期后 no-op。
func (s *Store) Capture(requestID string, body []byte) {
	if s == nil || requestID == "" || len(body) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled || s.expired() {
		return
	}

	// P1-04.1：真实内存上界——只分配 min(len(body), maxBytes)，
	// 绝不先全量拷贝再切片（否则 10MiB 请求会瞬时分配 10MiB）。
	n := len(body)
	truncated := false
	if n > s.maxBytes {
		n = s.maxBytes
		truncated = true
	}
	b := make([]byte, n)
	copy(b, body[:n])

	// 同 requestID 重复捕获：旧 Body best-effort 置零后再覆盖
	if old, ok := s.entries[requestID]; ok {
		zeroBytes(old.Body)
		s.removeOrder(requestID)
	} else if len(s.entries) >= s.maxEntries {
		// 容量满：淘汰最旧（best-effort 置零）
		if len(s.order) > 0 {
			oldest := s.order[0]
			s.order = s.order[1:]
			if old, ok := s.entries[oldest]; ok {
				zeroBytes(old.Body)
				delete(s.entries, oldest)
			}
		}
	}

	s.entries[requestID] = &Entry{
		RequestID:  requestID,
		Body:       b,
		CapturedAt: s.now(),
		Truncated:  truncated,
	}
	s.order = append(s.order, requestID)
}

// Get: 按 requestID 读取捕获正文（disabled/过期/不存在 → false）。
// 返回 Body 的副本。
func (s *Store) Get(requestID string) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled || s.expired() {
		return Entry{}, false
	}
	e, ok := s.entries[requestID]
	if !ok {
		return Entry{}, false
	}
	cp := make([]byte, len(e.Body))
	copy(cp, e.Body)
	return Entry{RequestID: e.RequestID, Body: cp, CapturedAt: e.CapturedAt, Truncated: e.Truncated}, true
}

// Enabled: 当前是否处于可捕获状态。
func (s *Store) Enabled() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled && !s.expired()
}

func (s *Store) expired() bool { // caller holds lock
	return !s.expiresAt.IsZero() && s.now().After(s.expiresAt)
}

// disableAndClear: 立即停用并清空（timer 触发或显式调用）。
func (s *Store) disableAndClear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled = false
	for _, e := range s.entries {
		zeroBytes(e.Body)
	}
	s.entries = make(map[string]*Entry)
	s.order = nil
}

func (s *Store) removeOrder(requestID string) { // caller holds lock
	for i, id := range s.order {
		if id == requestID {
			s.order = append(s.order[:i], s.order[i+1:]...)
			return
		}
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
