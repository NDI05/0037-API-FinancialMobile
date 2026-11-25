package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pam/recap/backend-go/internal/categoryllm"
	"github.com/pam/recap/backend-go/internal/gmail"
	"github.com/pam/recap/backend-go/internal/store"
)

func TestInitialBackfillHoldsCategoryQueueUntilEveryMonthCompletes(t *testing.T) {
	stub := &stubCategory{}
	h := newCategoryHarness(t, stub)
	h.register("initial-category@example.test")
	token, _ := h.login("initial-category@example.test")
	h.grantCategoryConsent(token)
	txID := h.queueTx(token, "d"+strings.Repeat("1", 31), "BAKSO UJI", "QRIS BAKSO")
	ctx := context.Background()
	owner, now := h.ownerID(), h.api.Now()
	service := gmail.NewService(h.store, nil, nil, gmail.Settings{}, testLogger())
	h.api.SetGmail(service, nil)
	if _, err := h.store.SaveGmailConnection(ctx, store.GmailConnectionInput{
		OwnerID: owner, AccountEmail: "initial-category@gmail.test",
		RefreshToken: "fixture-only", Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if queued, err := h.api.EnqueueImported(ctx, owner, []string{txID}); err != nil || queued != 1 {
		t.Fatalf("enqueue=%d err=%v", queued, err)
	}
	if err := h.api.DrainOwner(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if status, body := h.request("POST", "/v1/category-jobs/drain", token, nil); status != 200 || body["state"] != "not_due" {
		t.Fatalf("drain=%d %v", status, body)
	}
	if status, body := h.request("POST", "/v1/category-jobs", token, map[string]any{"transactionIds": []string{txID}}); status != 200 {
		t.Fatalf("manual category request=%d %v", status, body)
	}
	NewCategoryWorker(h.api).tick()
	if stub.calls != 0 || h.pendingQueue() != 1 {
		t.Fatalf("category work ran before initial coverage: calls=%d pending=%d", stub.calls, h.pendingQueue())
	}

	zone := time.FixedZone("WIB", 7*60*60)
	local := now.In(zone)
	monthStart := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, zone)
	for offset := 0; offset <= 12; offset++ {
		start := monthStart.AddDate(0, -offset, 0)
		job, err := h.store.EnsureGmailBackfillJob(ctx, owner, start.Format("2006-01"), start, start.AddDate(0, 1, 0), now)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.store.FinishGmailSyncJob(ctx, owner, job.ID, "COMPLETE", "", now); err != nil {
			t.Fatal(err)
		}
		if offset == 11 {
			NewCategoryWorker(h.api).tick()
			if stub.calls != 0 {
				t.Fatalf("oldest partial month was bypassed: calls=%d", stub.calls)
			}
		}
	}
	NewCategoryWorker(h.api).tick()
	NewCategoryWorker(h.api).tick()
	if stub.calls != 1 || h.pendingQueue() != 0 {
		t.Fatalf("completed coverage drain: calls=%d pending=%d", stub.calls, h.pendingQueue())
	}
	if waiting, err := service.InitialBackfillPending(ctx, owner, now.AddDate(0, 1, 0)); err != nil || waiting {
		t.Fatalf("new calendar month reopened initial gate: waiting=%t err=%v", waiting, err)
	}
}

// These tests cover the server-side half of the Gmail category bridge: the Gmail worker calls
// EnqueueImported/DrainOwner after an acknowledged import page, exactly like this.

// A server-side import must not enqueue or classify without AI_CATEGORIZATION consent, and the
// enqueue leg must never call the provider. A replay of the same ids adds no duplicate job.
func TestServerSideImportEnqueueConsentGatedAndProviderFree(t *testing.T) {
	stub := &stubCategory{}
	h := newCategoryHarness(t, stub)
	h.register("gmail-cat@example.test")
	token, _ := h.login("gmail-cat@example.test")
	txID := h.queueTx(token, "d"+strings.Repeat("0", 31), "BAKSO UJI", "QRIS BAKSO")
	ctx := context.Background()
	owner := h.ownerID()

	queued, err := h.api.EnqueueImported(ctx, owner, []string{txID})
	if err != nil || queued != 0 {
		t.Fatalf("consent gate leaked: queued=%d err=%v", queued, err)
	}
	if stub.calls != 0 || h.pendingQueue() != 0 {
		t.Fatalf("no-consent enqueue must stay silent: calls=%d pending=%d", stub.calls, h.pendingQueue())
	}

	h.grantCategoryConsent(token)
	queued, err = h.api.EnqueueImported(ctx, owner, []string{txID})
	if err != nil || queued != 1 || h.pendingQueue() != 1 {
		t.Fatalf("enqueue queued=%d pending=%d err=%v", queued, h.pendingQueue(), err)
	}
	if stub.calls != 0 {
		t.Fatalf("server-side enqueue called the provider %d times", stub.calls)
	}
	// Replayed import page: the same ids must not add a second job.
	queued, err = h.api.EnqueueImported(ctx, owner, []string{txID})
	if err != nil || queued != 0 || h.pendingQueue() != 1 {
		t.Fatalf("replay queued=%d pending=%d err=%v", queued, h.pendingQueue(), err)
	}

	// Drain the window: the imported row is classified through the existing pipeline.
	if err := h.api.DrainOwner(ctx, owner); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if stub.calls != 1 {
		t.Fatalf("drain provider calls=%d want 1", stub.calls)
	}
	_, tx := h.request("GET", "/v1/transactions/"+txID, token, nil)
	if tx["categoryCode"] != "food" || tx["categoryOrigin"] != "LLM" {
		t.Fatalf("imported row not classified: %v", tx)
	}
	// An empty/fresh window must not spend provider budget again.
	if err := h.api.DrainOwner(ctx, owner); err != nil {
		t.Fatalf("second drain: %v", err)
	}
	if stub.calls != 1 {
		t.Fatalf("second drain called the provider: %d", stub.calls)
	}
}

// The server-side drain must honour the durable budget gate: no provider call, no row deletion.
func TestServerSideImportDrainStopsAtBudgetGate(t *testing.T) {
	stub := &countingCategory{}
	h := newCategoryHarnessWithEnv(t, stub, map[string]string{
		"CATEGORY_LLM_DAILY_CEILING_USD": "0.00001",
	})
	h.register("gmail-budget@example.test")
	token, _ := h.login("gmail-budget@example.test")
	h.grantCategoryConsent(token)
	txID := h.queueTx(token, "e"+strings.Repeat("0", 31), "BAKSO UJI", "QRIS BAKSO")
	ctx := context.Background()
	owner := h.ownerID()

	if queued, err := h.api.EnqueueImported(ctx, owner, []string{txID}); err != nil || queued != 1 {
		t.Fatalf("enqueue queued=%d err=%v", queued, err)
	}
	if err := h.api.DrainOwner(ctx, owner); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if stub.count() != 0 {
		t.Fatalf("budget gate let the provider run %d times", stub.count())
	}
	_, tx := h.request("GET", "/v1/transactions/"+txID, token, nil)
	if code := tx["categoryCode"]; code != "" && code != "uncategorized" {
		t.Fatalf("budget-denied row must stay uncategorized: %v", tx)
	}
	if h.pendingQueue() == 0 {
		t.Fatal("budget-denied job was dropped instead of kept pending")
	}
}

// One window must never send more than CategoryDrainBatch merchants per provider request, nor more
// than CategoryDrainMaxBatches requests, and it must stop when the queue is empty.
func TestServerSideImportDrainBatchesAtMostFive(t *testing.T) {
	stub := &countingCategory{}
	var sizes []int
	stub.onClassify = func(candidates []categoryllm.Candidate) { sizes = append(sizes, len(candidates)) }
	h := newCategoryHarness(t, stub)
	h.register("gmail-batch@example.test")
	token, _ := h.login("gmail-batch@example.test")
	h.grantCategoryConsent(token)
	ctx := context.Background()
	owner := h.ownerID()

	ids := make([]string, 0, 7)
	for i := 0; i < 7; i++ {
		ids = append(ids, h.queueTx(token, "f"+string(rune('a'+i))+strings.Repeat("0", 30),
			"BAKSO UJI "+string(rune('A'+i)), "QRIS BAKSO"))
	}
	if queued, err := h.api.EnqueueImported(ctx, owner, ids); err != nil || queued != 7 {
		t.Fatalf("enqueue queued=%d err=%v", queued, err)
	}
	if err := h.api.DrainOwner(ctx, owner); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(sizes) == 0 || len(sizes) > CategoryDrainMaxBatches {
		t.Fatalf("provider requests=%v, want 1..%d", sizes, CategoryDrainMaxBatches)
	}
	for _, size := range sizes {
		if size > CategoryDrainBatch {
			t.Fatalf("provider request carried %d merchants, limit %d", size, CategoryDrainBatch)
		}
	}
	// 7 merchants at 5 per request = exactly 5 + 2.
	if len(sizes) != 2 || sizes[0] != 5 || sizes[1] != 2 {
		t.Fatalf("batch sizes=%v, want [5 2]", sizes)
	}
}

// A concurrent drain (HTTP poll, recovery worker or another import pass) owns the owner's window;
// the second trigger is answered not_due instead of spending provider budget in parallel.
func TestServerSideDrainIsSingleFlightPerOwner(t *testing.T) {
	stub := &stubCategory{}
	h := newCategoryHarness(t, stub)
	h.register("gmail-single@example.test")
	token, _ := h.login("gmail-single@example.test")
	h.grantCategoryConsent(token)
	txID := h.queueTx(token, "1"+strings.Repeat("0", 31), "BAKSO UJI", "QRIS BAKSO")
	ctx := context.Background()
	owner := h.ownerID()
	if queued, err := h.api.EnqueueImported(ctx, owner, []string{txID}); err != nil || queued != 1 {
		t.Fatalf("enqueue queued=%d err=%v", queued, err)
	}

	unlock, ok := h.api.acquireOwnerDrain(owner)
	if !ok {
		t.Fatal("owner drain lock is already held")
	}
	if err := h.api.DrainOwner(ctx, owner); err != nil {
		t.Fatalf("contended drain: %v", err)
	}
	if stub.calls != 0 {
		t.Fatalf("contended drain called the provider %d times", stub.calls)
	}
	unlock()

	if err := h.api.DrainOwner(ctx, owner); err != nil {
		t.Fatalf("drain after release: %v", err)
	}
	if stub.calls != 1 {
		t.Fatalf("released drain provider calls=%d want 1", stub.calls)
	}
}

// Server-side enqueue re-checks stored rows: a USER category decision is final, an internal transfer
// is skipped, and ids belonging to another owner are never picked up (owner isolation).
func TestServerSideEnqueueSkipsIneligibleAndForeignIDs(t *testing.T) {
	stub := &stubCategory{}
	h := newCategoryHarness(t, stub)
	h.register("gmail-owner-a@example.test")
	token, _ := h.login("gmail-owner-a@example.test")
	h.grantCategoryConsent(token)
	ctx := context.Background()
	ownerA := h.ownerID()

	decided := h.queueTx(token, "2"+strings.Repeat("0", 31), "BAKSO UJI", "QRIS BAKSO")
	status, current := h.request("GET", "/v1/transactions/"+decided, token, nil)
	if status != 200 {
		t.Fatalf("get tx=%d", status)
	}
	if status, _ = h.request("PATCH", "/v1/transactions/"+decided, token,
		map[string]any{"categoryId": h.categoryID("food"), "revision": current["revision"]}); status != 200 {
		t.Fatalf("user override patch=%d", status)
	}
	// A different owner exists but must never gain this row's work.
	h.register("gmail-owner-b@example.test")
	ownerB := store.OwnerIDForEmail("gmail-owner-b@example.test")

	if queued, err := h.api.EnqueueImported(ctx, ownerB, []string{decided}); err != nil || queued != 0 {
		t.Fatalf("foreign owner enqueued queued=%d err=%v", queued, err)
	}
	if h.pendingQueue() != 0 {
		t.Fatalf("foreign owner enqueued into owner A's queue: pending=%d", h.pendingQueue())
	}
	if queued, err := h.api.EnqueueImported(ctx, ownerA, []string{decided}); err != nil || queued != 0 {
		t.Fatalf("USER decision was enqueued: queued=%d err=%v", queued, err)
	}
	if stub.calls != 0 {
		t.Fatalf("enqueue-only path called the provider %d times", stub.calls)
	}
}
