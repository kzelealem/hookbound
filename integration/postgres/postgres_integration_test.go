//go:build integration

package postgresintegration

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kzelealem/hookbound"
	hookboundpg "github.com/kzelealem/hookbound/postgres"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var integrationDatabaseURL string

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)

	databaseURL := os.Getenv("HOOKBOUND_TEST_DATABASE_URL")
	cleanup := func() {}
	if databaseURL == "" {
		var err error
		databaseURL, cleanup, err = startPostgresContainer(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	integrationDatabaseURL = withSearchPath(databaseURL, "pg_catalog")
	cancel()
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func TestConcurrentMigrationsUseCustomSchema(t *testing.T) {
	db := openDatabase(t)
	schema := testSchema(t)

	var wait sync.WaitGroup
	errorsFound := make(chan error, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsFound <- hookboundpg.MigrateWithConfig(context.Background(), db, hookboundpg.MigrationConfig{Schema: schema})
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("concurrent migration failed: %v", err)
		}
	}

	var count int
	query := fmt.Sprintf(`SELECT count(*) FROM %s.hookbound_schema_migrations`, quoteIdentifier(schema))
	if err := db.QueryRowContext(context.Background(), query).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("expected 3 applied migrations, got %d", count)
	}
	assertCurrentSearchPathCannotSeeHookboundTables(t, db)

	if _, err := db.ExecContext(context.Background(), fmt.Sprintf(`
		UPDATE %s.hookbound_schema_migrations SET checksum = 'tampered' WHERE name = '001_init.sql'`, quoteIdentifier(schema))); err != nil {
		t.Fatal(err)
	}
	err := hookboundpg.MigrateWithConfig(context.Background(), db, hookboundpg.MigrationConfig{Schema: schema})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("migration checksum drift was not rejected: %v", err)
	}
}

func TestIdempotentPublicationIsRaceSafe(t *testing.T) {
	db, store, schema := newStore(t, nil)
	request := hookbound.SendRequest{
		URL:       "https://example.com/webhooks",
		EventType: "invoice.paid.v1",
		Body:      []byte(`{"invoice_id":"inv_42"}`),
	}
	options := hookboundpg.EnqueueOptions{IdempotencyKey: "tenant-7:invoice:inv_42:endpoint-3"}

	const workers = 32
	publications := make(chan hookboundpg.Publication, workers)
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			publication, err := store.EnqueueWithOptions(context.Background(), request, options)
			publications <- publication
			errorsFound <- err
		}()
	}
	wait.Wait()
	close(publications)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("idempotent enqueue failed: %v", err)
		}
	}
	var first hookboundpg.Publication
	for publication := range publications {
		if first == (hookboundpg.Publication{}) {
			first = publication
		}
		if publication != first {
			t.Fatalf("idempotent enqueue returned different publications: first=%+v current=%+v", first, publication)
		}
	}
	assertTableCount(t, db, schema, "hookbound_messages", 1)
	assertTableCount(t, db, schema, "hookbound_deliveries", 1)

	request.Body = []byte(`{"invoice_id":"inv_other"}`)
	_, err := store.EnqueueWithOptions(context.Background(), request, options)
	if hookbound.ErrorCode(err) != hookbound.CodeConflict {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}

func TestInboundReceiptDeduplicationIsRaceSafe(t *testing.T) {
	db, store, schema := newStore(t, nil)
	message := hookbound.VerifiedMessage{
		ID: "msg_inbound_race", Type: "invoice.paid.v1", Source: "provider",
		Timestamp: time.Now().UTC(), Body: []byte(`{"invoice_id":"inv_42"}`), ContentType: "application/json",
	}

	const workers = 32
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsFound <- store.Handle(context.Background(), message)
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("duplicate receipt failed: %v", err)
		}
	}
	assertTableCount(t, db, schema, "hookbound_receipts", 1)

	message.Body = []byte(`{"invoice_id":"different"}`)
	if err := store.Handle(context.Background(), message); hookbound.ErrorCode(err) != hookbound.CodeConflict {
		t.Fatalf("expected receipt content conflict, got %v", err)
	}
}

func TestClaimingUsesSkipLockedWithoutDuplicates(t *testing.T) {
	_, store, _ := newStore(t, nil)
	const deliveries = 16
	for index := range deliveries {
		_, err := store.Enqueue(context.Background(), hookbound.SendRequest{
			URL:       "https://example.com/webhooks/" + strconv.Itoa(index),
			EventType: "test.created.v1",
			Body:      []byte(strconv.Itoa(index)),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	claimed := make(chan *hookboundpg.ClaimedDelivery, deliveries)
	errorsFound := make(chan error, deliveries)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range deliveries {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			value, err := store.ClaimDelivery(context.Background(), time.Minute)
			claimed <- value
			errorsFound <- err
		}()
	}
	close(start)
	wait.Wait()
	close(claimed)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatalf("claim failed: %v", err)
		}
	}
	seen := make(map[string]struct{}, deliveries)
	for value := range claimed {
		if value == nil {
			t.Fatal("expected a claimed delivery")
		}
		if _, exists := seen[value.DeliveryID]; exists {
			t.Fatalf("delivery %s was claimed more than once", value.DeliveryID)
		}
		seen[value.DeliveryID] = struct{}{}
	}
	if len(seen) != deliveries {
		t.Fatalf("expected %d unique claims, got %d", deliveries, len(seen))
	}
}

func TestDeliveryAndReceiptLeasesRenewWithoutResurrection(t *testing.T) {
	clock := &mutableClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	_, store, _ := newStore(t, clock)
	_, err := store.Enqueue(context.Background(), hookbound.SendRequest{
		URL: "https://example.com/webhooks", EventType: "lease.test.v1", Body: []byte("delivery"),
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimDelivery(context.Background(), time.Minute)
	if err != nil || claimed == nil {
		t.Fatalf("claim delivery: claimed=%v err=%v", claimed, err)
	}
	clock.Set(clock.Now().Add(30 * time.Second))
	if err := store.RenewDeliveryLease(context.Background(), claimed, time.Minute); err != nil {
		t.Fatal(err)
	}
	clock.Set(time.Date(2026, 7, 14, 12, 1, 10, 0, time.UTC))
	other, err := store.ClaimDelivery(context.Background(), time.Minute)
	if err != nil || other != nil {
		t.Fatalf("renewed delivery was reclaimed early: claimed=%v err=%v", other, err)
	}
	clock.Set(time.Date(2026, 7, 14, 12, 1, 31, 0, time.UTC))
	reclaimed, err := store.ClaimDelivery(context.Background(), time.Minute)
	if err != nil || reclaimed == nil || reclaimed.Attempt != 2 {
		t.Fatalf("expired delivery was not reclaimed: claimed=%+v err=%v", reclaimed, err)
	}
	if err := store.RenewDeliveryLease(context.Background(), claimed, time.Minute); hookbound.ErrorCode(err) != hookbound.CodeConflict {
		t.Fatalf("stale delivery claim renewed: %v", err)
	}

	message := hookbound.VerifiedMessage{
		ID: "msg_receipt_lease", Type: "receipt.test.v1", Source: "integration",
		Timestamp: clock.Now(), Body: []byte("receipt"), ContentType: "application/json",
	}
	if err := store.Handle(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.ClaimReceipt(context.Background(), time.Minute)
	if err != nil || receipt == nil {
		t.Fatalf("claim receipt: claimed=%v err=%v", receipt, err)
	}
	clock.Set(clock.Now().Add(20 * time.Second))
	if err := store.RenewReceiptLease(context.Background(), receipt, time.Minute); err != nil {
		t.Fatal(err)
	}
	clock.Set(clock.Now().Add(61 * time.Second))
	if err := store.RenewReceiptLease(context.Background(), receipt, time.Minute); hookbound.ErrorCode(err) != hookbound.CodeConflict {
		t.Fatalf("expired receipt lease was resurrected: %v", err)
	}
}

func TestRuntimeHeartbeatPreventsPrematureReclaim(t *testing.T) {
	_, store, _ := newStore(t, nil)
	if _, err := store.Enqueue(context.Background(), hookbound.SendRequest{
		URL: "https://example.com/webhooks", EventType: "heartbeat.test.v1", Body: []byte("slow delivery"),
	}); err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	sender, err := hookbound.NewSender(hookbound.SenderConfig{
		Signer: noopSigner{},
		UnsafeHTTPClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			close(started)
			select {
			case <-release:
			case <-request.Context().Done():
				return nil, request.Context().Err()
			}
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    request,
			}, nil
		})},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := hookboundpg.NewRuntime(hookboundpg.RuntimeConfig{
		Store: store, Sender: sender,
		LeaseDuration:        2 * time.Second,
		LeaseRenewalInterval: 250 * time.Millisecond,
		LeaseRenewalTimeout:  150 * time.Millisecond,
		CompletionTimeout:    2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	workDone := make(chan error, 1)
	go func() {
		worked, err := runtime.WorkOutboundOnce(context.Background())
		if !worked && err == nil {
			err = fmt.Errorf("runtime reported no work")
		}
		workDone <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("outbound attempt did not start")
	}
	time.Sleep(2500 * time.Millisecond)
	claimed, err := store.ClaimDelivery(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if claimed != nil {
		t.Fatalf("heartbeat-protected delivery was reclaimed: %+v", claimed)
	}
	close(release)
	select {
	case err := <-workDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("outbound worker did not complete")
	}
	claimed, err = store.ClaimDelivery(context.Background(), time.Second)
	if err != nil || claimed != nil {
		t.Fatalf("completed delivery remained claimable: claimed=%+v err=%v", claimed, err)
	}
}

func TestRetentionCleanupIsBoundedAndTerminalOnly(t *testing.T) {
	db, store, schema := newStore(t, nil)
	ctx := context.Background()

	for _, outcome := range []hookbound.Outcome{hookbound.OutcomeDelivered, hookbound.OutcomePermanentFailure} {
		if _, err := store.Enqueue(ctx, hookbound.SendRequest{
			URL: "https://example.com/webhooks", EventType: "cleanup.test.v1", Body: []byte(outcome.String()),
		}); err != nil {
			t.Fatal(err)
		}
		claimed, err := store.ClaimDelivery(ctx, time.Minute)
		if err != nil || claimed == nil {
			t.Fatalf("claim terminal delivery: claimed=%v err=%v", claimed, err)
		}
		if err := store.CompleteDelivery(ctx, claimed, hookbound.AttemptResult{Outcome: outcome}, nil, hookbound.StandardRetryPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Enqueue(ctx, hookbound.SendRequest{
		URL: "https://example.com/pending", EventType: "cleanup.pending.v1", Body: []byte("pending"),
	}); err != nil {
		t.Fatal(err)
	}
	message := hookbound.VerifiedMessage{
		ID: "msg_cleanup_receipt", Type: "cleanup.receipt.v1", Source: "integration",
		Timestamp: time.Now().UTC(), Body: []byte("receipt"), ContentType: "application/json",
	}
	if err := store.Handle(ctx, message); err != nil {
		t.Fatal(err)
	}
	receipt, err := store.ClaimReceipt(ctx, time.Minute)
	if err != nil || receipt == nil {
		t.Fatalf("claim receipt: claimed=%v err=%v", receipt, err)
	}
	if err := store.CompleteReceipt(ctx, receipt, nil, hookbound.StandardRetryPolicy()); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ExecContext(ctx, fmt.Sprintf(`
		UPDATE %s.hookbound_deliveries SET completed_at = clock_timestamp() - interval '48 hours'
		WHERE state IN ('delivered','permanent_failure');
		UPDATE %s.hookbound_receipts SET processed_at = clock_timestamp() - interval '48 hours'
		WHERE state = 'processed'`, quoteIdentifier(schema), quoteIdentifier(schema))); err != nil {
		t.Fatal(err)
	}
	result, err := store.Cleanup(ctx, hookboundpg.RetentionPolicy{
		DeliveredRetention:      24 * time.Hour,
		FailedDeliveryRetention: 24 * time.Hour,
		ReceiptRetention:        24 * time.Hour,
		OrphanMessageRetention:  time.Nanosecond,
		BatchSize:               10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.DeliveredDeliveries != 1 || result.FailedDeliveries != 1 || result.Receipts != 1 || result.OrphanMessages != 2 {
		t.Fatalf("unexpected cleanup result: %+v", result)
	}
	assertTableCount(t, db, schema, "hookbound_deliveries", 1)
	assertTableCount(t, db, schema, "hookbound_messages", 1)
	assertTableCount(t, db, schema, "hookbound_receipts", 0)
}

func newStore(t *testing.T, clock hookbound.Clock) (*sql.DB, *hookboundpg.Store, string) {
	t.Helper()
	db := openDatabase(t)
	schema := testSchema(t)
	if err := hookboundpg.MigrateWithConfig(context.Background(), db, hookboundpg.MigrationConfig{Schema: schema}); err != nil {
		t.Fatal(err)
	}
	store, err := hookboundpg.NewStoreWithConfig(db, hookboundpg.StoreConfig{Schema: schema, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return db, store, schema
}

func openDatabase(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", integrationDatabaseURL)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(64)
	db.SetMaxIdleConns(16)
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func testSchema(t *testing.T) string {
	t.Helper()
	var base strings.Builder
	for _, character := range strings.ToLower(t.Name()) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			base.WriteRune(character)
		} else {
			base.WriteByte('_')
		}
	}
	suffix := "_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	maximumBase := 63 - len("hb_") - len(suffix)
	baseName := base.String()
	if len(baseName) > maximumBase {
		baseName = baseName[:maximumBase]
	}
	schema := "hb_" + baseName + suffix
	t.Cleanup(func() {
		db, err := sql.Open("pgx", integrationDatabaseURL)
		if err == nil {
			_, _ = db.ExecContext(context.Background(), fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, quoteIdentifier(schema)))
			_ = db.Close()
		}
	})
	return schema
}

func assertCurrentSearchPathCannotSeeHookboundTables(t *testing.T, db *sql.DB) {
	t.Helper()
	var value int
	err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM hookbound_messages`).Scan(&value)
	if err == nil {
		t.Fatal("unqualified Hookbound table unexpectedly resolved through search_path")
	}
}

func assertTableCount(t *testing.T, db *sql.DB, schema, table string, expected int) {
	t.Helper()
	query := fmt.Sprintf(`SELECT count(*) FROM %s.%s`, quoteIdentifier(schema), quoteIdentifier(table))
	var count int
	if err := db.QueryRowContext(context.Background(), query).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("expected %s.%s count %d, got %d", schema, table, expected, count)
	}
}

func quoteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func withSearchPath(databaseURL, searchPath string) string {
	separator := "?"
	if strings.Contains(databaseURL, "?") {
		separator = "&"
	}
	return databaseURL + separator + "search_path=" + searchPath
}

func startPostgresContainer(ctx context.Context) (string, func(), error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", nil, fmt.Errorf("PostgreSQL integration tests require Docker or HOOKBOUND_TEST_DATABASE_URL: %w", err)
	}
	if output, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("PostgreSQL integration tests require a running Docker daemon: %w: %s", err, strings.TrimSpace(string(output)))
	}
	name := "hookbound-postgres-" + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	image := strings.TrimSpace(os.Getenv("HOOKBOUND_POSTGRES_IMAGE"))
	if image == "" {
		image = "postgres:17-alpine"
	}
	if strings.HasPrefix(image, "-") || strings.ContainsAny(image, " \t\r\n\x00") {
		return "", nil, fmt.Errorf("HOOKBOUND_POSTGRES_IMAGE is not a valid image reference")
	}
	command := exec.CommandContext(ctx, "docker", "run", "--detach", "--rm",
		"--name", name,
		"--env", "POSTGRES_USER=hookbound",
		"--env", "POSTGRES_PASSWORD=hookbound",
		"--env", "POSTGRES_DB=hookbound",
		"--publish", "127.0.0.1::5432",
		image)
	if output, err := command.CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("start PostgreSQL container: %w: %s", err, strings.TrimSpace(string(output)))
	}
	cleanup := func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = exec.CommandContext(stopCtx, "docker", "rm", "--force", name).Run()
	}
	portOutput, err := exec.CommandContext(ctx, "docker", "port", name, "5432/tcp").CombinedOutput()
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("read PostgreSQL container port: %w: %s", err, strings.TrimSpace(string(portOutput)))
	}
	address := strings.TrimSpace(string(portOutput))
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("parse PostgreSQL container port %q: %w", address, err)
	}
	databaseURL := "postgres://hookbound:hookbound@127.0.0.1:" + port + "/hookbound?sslmode=disable"
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	defer db.Close()
	for {
		pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := db.PingContext(pingCtx)
		cancel()
		if err == nil {
			return databaseURL, cleanup, nil
		}
		select {
		case <-ctx.Done():
			cleanup()
			return "", nil, fmt.Errorf("wait for PostgreSQL container: %w", ctx.Err())
		case <-time.After(250 * time.Millisecond):
		}
	}
}

type mutableClock struct {
	mu  sync.RWMutex
	now time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *mutableClock) Set(value time.Time) {
	c.mu.Lock()
	c.now = value
	c.mu.Unlock()
}

type noopSigner struct{}

func (noopSigner) Sign(context.Context, hookbound.SignInput) (http.Header, error) {
	return make(http.Header), nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
