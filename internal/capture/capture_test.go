package capture

// P1-04C · Memory Capture Store Gate（SEC-003）
//
// 覆盖：bounded eviction、截断、expiry timer 自动清空、新 store 为空、
// 并发 Capture/Get（配合 go test -race）、disabled/nil 安全。
// 注意：正文只在内存——不存在任何落盘路径可测（落盘归零由 Prompt Privacy Gate 全链覆盖）。

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func fixedNow(at time.Time) func() time.Time { return func() time.Time { return at } }

// 7. bounded eviction：达 maxEntries 淘汰最旧
func TestCaptureStore_BoundedEviction(t *testing.T) {
	start := time.Now()
	s := NewStore(true, start.Add(time.Hour), 1024, 3)
	s.now = fixedNow(start)
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		s.Capture(id, []byte("body-"+id))
	}
	if _, ok := s.Get("r1"); ok {
		t.Fatal("[安全回归失败] 最旧条目 r1 应被淘汰")
	}
	if _, ok := s.Get("r2"); ok {
		t.Fatal("[安全回归失败] r2 应被淘汰")
	}
	for _, id := range []string{"r3", "r4", "r5"} {
		if e, ok := s.Get(id); !ok || string(e.Body) != "body-"+id {
			t.Fatalf("[安全回归失败] %s 应保留且内容一致", id)
		}
	}
}

// 8. body truncation：超 maxBytes 截断并标记
func TestCaptureStore_Truncation(t *testing.T) {
	start := time.Now()
	s := NewStore(true, start.Add(time.Hour), 10, 10)
	s.now = fixedNow(start)
	s.Capture("big", []byte(strings.Repeat("A", 100)))
	e, ok := s.Get("big")
	if !ok {
		t.Fatal("条目应存在")
	}
	if len(e.Body) != 10 {
		t.Fatalf("[安全回归失败] 应截断至 10 字节，实际 %d", len(e.Body))
	}
	if !e.Truncated {
		t.Fatal("[安全回归失败] Truncated 标记缺失")
	}
}

// 9. expiry timer 自动清空 + 禁止新捕获
func TestCaptureStore_ExpiryTimerAutoClear(t *testing.T) {
	start := time.Now()
	s := NewStore(true, start.Add(80*time.Millisecond), 1024, 10)
	s.Capture("before", []byte("x"))

	// 未过期：可读
	if _, ok := s.Get("before"); !ok {
		t.Fatal("过期前应可读")
	}
	time.Sleep(250 * time.Millisecond) // 等待 timer 触发
	if s.Enabled() {
		t.Fatal("[安全回归失败] 到期后应自动 disable")
	}
	if _, ok := s.Get("before"); ok {
		t.Fatal("[安全回归失败] 到期后应清空")
	}
	s.Capture("after", []byte("y")) // 到期后捕获必须 no-op
	if _, ok := s.Get("after"); ok {
		t.Fatal("[安全回归失败] 到期后新捕获应被拒绝")
	}
}

// 10. restart/新 store → empty
func TestCaptureStore_NewStoreEmpty(t *testing.T) {
	s := NewStore(true, time.Now().Add(time.Hour), 1024, 10)
	if _, ok := s.Get("anything"); ok {
		t.Fatal("[安全回归失败] 新 store 应为空")
	}
}

// 11. concurrent Capture/Get 无 race（go test -race 下运行）
func TestCaptureStore_ConcurrentAccess(t *testing.T) {
	s := NewStore(true, time.Now().Add(time.Hour), 64*1024, 100)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				id := string(rune('a'+i)) + string(rune('a'+j%26)) + "-id"
				s.Capture(id, []byte(strings.Repeat("x", 100)))
				_, _ = s.Get(id)
				_ = s.Enabled()
			}
		}(i)
	}
	wg.Wait()
}

// disabled store / nil store 安全
func TestCaptureStore_DisabledAndNil(t *testing.T) {
	s := NewStore(false, time.Now().Add(time.Hour), 1024, 10)
	s.Capture("x", []byte("y"))
	if _, ok := s.Get("x"); ok {
		t.Fatal("[安全回归失败] disabled store 不得捕获")
	}
	if s.Enabled() {
		t.Fatal("[安全回归失败] disabled store Enabled 应为 false")
	}
	var nilStore *Store
	nilStore.Capture("x", []byte("y"))
	if _, ok := nilStore.Get("x"); ok {
		t.Fatal("[安全回归失败] nil store 应安全 no-op")
	}
	if nilStore.Enabled() {
		t.Fatal("[安全回归失败] nil store Enabled 应为 false")
	}
}

// Get 返回副本：修改返回值不得污染内部状态
func TestCaptureStore_GetReturnsCopy(t *testing.T) {
	start := time.Now()
	s := NewStore(true, start.Add(time.Hour), 1024, 10)
	s.now = fixedNow(start)
	s.Capture("id", []byte("original"))
	e, _ := s.Get("id")
	for i := range e.Body {
		e.Body[i] = 'Z'
	}
	again, _ := s.Get("id")
	if string(again.Body) != "original" {
		t.Fatal("[安全回归失败] Get 必须返回副本")
	}
}

// I. P1-04.1：>64KiB 输入 → 实际存储恰为硬上限（分配路径只复制 cap）
func TestCaptureStore_HardCapAllocationPath(t *testing.T) {
	s := NewStore(true, time.Now().Add(time.Hour), 64*1024, 10)
	big := strings.Repeat("P", 100*1024)
	s.Capture("huge", []byte(big))
	e, ok := s.Get("huge")
	if !ok {
		t.Fatal("条目应存在")
	}
	if len(e.Body) != 64*1024 {
		t.Fatalf("[安全回归失败] 应恰好保留 64KiB，实际 %d", len(e.Body))
	}
	if !e.Truncated {
		t.Fatal("[安全回归失败] Truncated 应为 true")
	}
}
