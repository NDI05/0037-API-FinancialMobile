package httpapi

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/categoryllm"
)

// splitCategory models a classifier whose SplitCandidates turns one merchant batch into several
// provider calls (2 merchants per call). This is the shape that made the old batch-iteration cap
// under-count real provider requests.
type splitCategory struct {
	failingCategory
	mu    sync.Mutex
	calls int
	sizes []int
}

func (c *splitCategory) SplitCandidates(cs []categoryllm.Candidate) [][]categoryllm.Candidate {
	var groups [][]categoryllm.Candidate
	for len(cs) > 0 {
		n := 2
		if len(cs) < n {
			n = len(cs)
		}
		groups = append(groups, cs[:n])
		cs = cs[n:]
	}
	return groups
}

func (c *splitCategory) Classify(ctx context.Context, candidates []categoryllm.Candidate) (categoryllm.Response, error) {
	c.mu.Lock()
	c.calls++
	c.sizes = append(c.sizes, len(candidates))
	c.mu.Unlock()
	return c.failingCategory.Classify(ctx, candidates)
}

func (c *splitCategory) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (h *harness) countJobs(state string) int {
	h.t.Helper()
	var n int
	if err := h.store.DB.QueryRow(
		`SELECT COUNT(*) FROM category_jobs WHERE state=?`, state).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// A 2-hour window must issue at most CategoryDrainMaxProviderCalls real provider requests even when
// every batch is split into several calls. Kandidat yang tidak sempat dipanggil tetap PENDING untuk
// jendela berikutnya: tidak hilang, tidak di-FAILED, dan tidak memakai jatah retry provider.
func TestDrainWindowCapsRealProviderRequestsAndKeepsRemainder(t *testing.T) {
	stub := &splitCategory{}
	h := newCategoryHarness(t, stub)
	h.register("window-cap@example.test")
	token, _ := h.login("window-cap@example.test")
	h.grantCategoryConsent(token)
	ctx := context.Background()
	owner := h.ownerID()

	ids := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		ids = append(ids, h.queueTx(token, fmt.Sprintf("9%031d", i),
			fmt.Sprintf("BAKSO W%02d", i), "QRIS BAKSO"))
	}
	if queued, err := h.api.EnqueueImported(ctx, owner, ids); err != nil || queued != 20 {
		t.Fatalf("enqueue queued=%d err=%v", queued, err)
	}

	now := time.Now()
	h.api.Now = func() time.Time { return now }
	if err := h.api.DrainOwner(ctx, owner); err != nil {
		t.Fatalf("window 1: %v", err)
	}
	if stub.count() != CategoryDrainMaxProviderCalls {
		t.Fatalf("window 1 provider calls=%d, cap=%d", stub.count(), CategoryDrainMaxProviderCalls)
	}
	for _, size := range stub.sizes {
		if size > CategoryDrainBatch {
			t.Fatalf("provider request carried %d merchants, batch cap %d", size, CategoryDrainBatch)
		}
	}
	firstPending := h.pendingQueue()
	if firstPending == 0 {
		t.Fatal("window stopped at the provider cap but dropped the remaining candidates")
	}
	if failed := h.countJobs("FAILED"); failed != 0 {
		t.Fatalf("provider cap permanently failed %d jobs", failed)
	}

	// The remainder is picked up by later windows, never permanently lost.
	previousCalls := stub.count()
	previousPending := firstPending
	windows := 0
	for h.pendingQueue() > 0 {
		if windows > 20 {
			t.Fatalf("queue did not drain: pending=%d", h.pendingQueue())
		}
		now = now.Add(CategoryDrainInterval + time.Minute)
		if err := h.api.DrainOwner(ctx, owner); err != nil {
			t.Fatalf("window %d: %v", windows+2, err)
		}
		if delta := stub.count() - previousCalls; delta > CategoryDrainMaxProviderCalls {
			t.Fatalf("window issued %d provider calls, cap %d", delta, CategoryDrainMaxProviderCalls)
		}
		if h.pendingQueue() > previousPending {
			t.Fatalf("pending grew from %d to %d", previousPending, h.pendingQueue())
		}
		previousCalls, previousPending = stub.count(), h.pendingQueue()
		windows++
	}
	var classified int
	if err := h.store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM transactions WHERE owner_id=? AND classifier_origin='LLM'`,
		owner).Scan(&classified); err != nil {
		t.Fatal(err)
	}
	if classified != 20 {
		t.Fatalf("classified=%d want 20 (candidates lost across windows)", classified)
	}
	if failed := h.countJobs("FAILED"); failed != 0 {
		t.Fatalf("%d jobs failed permanently", failed)
	}
}
