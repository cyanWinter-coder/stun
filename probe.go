// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/logging"
)

// ProbeMode controls whether a ProbeGroup retransmits requests that do not
// receive a matching response.
type ProbeMode int

const (
	// ProbeRetry retransmits a request with the same transaction ID until a
	// terminal response arrives, the per-probe attempt budget is exhausted, or
	// the group deadline / context fires. Back-off grows linearly with RTO,
	// matching the Client retransmission behavior.
	ProbeRetry ProbeMode = iota

	// ProbeNoRetry sends each request exactly once. It is intended for
	// transports that perform their own reliability (for example TCP) or for
	// callers that schedule retries externally.
	ProbeNoRetry
)

var (
	// ErrProbeGroupClosed indicates that the ProbeGroup has already been
	// closed.
	ErrProbeGroupClosed = errors.New("probe group is closed")

	// ErrProbeBudgetExhausted indicates that the group-wide request budget was
	// consumed before the request could be sent. No packet was written.
	ErrProbeBudgetExhausted = errors.New("probe group request budget exhausted")

	// ErrProbeMessageType indicates that a probe request is not a Binding
	// request, that a per-message target was given to a stream transport, or
	// that an incoming message does not belong to the Binding method.
	ErrProbeMessageType = errors.New("probe message has unexpected type or method")

	// ErrProbeTransactionID indicates that a caller supplied a transaction ID
	// that is still in use by an active probe of the same group.
	ErrProbeTransactionID = errors.New("probe transaction id is already in use")

	// ErrProbeConfig indicates an invalid ProbeConfig.
	ErrProbeConfig = errors.New("invalid probe configuration")
)

// ProbeResult is the single terminal event produced by a probe.
type ProbeResult struct {
	// TransactionID identifies the probe. It equals the request transaction
	// ID and is stable across every retransmission.
	TransactionID [TransactionIDSize]byte
	// Response is the validated success or error response. It is nil when
	// Error is set.
	Response *Message
	// Source is the address the response was received from. It is nil for
	// stream transports that do not expose per-message peer addresses.
	Source net.Addr
	// Error is set for timeouts, cancellations, transport failures or
	// validation failures. A STUN ERROR-CODE response is not reported here;
	// it is delivered as a validated Response.
	Error error
}

// ProbeConfig configures a ProbeGroup.
type ProbeConfig struct {
	// Conn carries STUN packets. It is typically a net.PacketConn (UDP). A
	// stream Connection (net.Conn) is supported for ProbeNoRetry.
	Conn Connection

	// Context bounds the whole group. When it is canceled all pending probes
	// are terminated and their waiters removed immediately. Defaults to
	// context.Background().
	Context context.Context //nolint:containedctx // configuration value, not a derived request context

	// Deadline is shared by every probe. The zero value means no group-wide
	// deadline; each Retry probe is still bounded by its attempt budget.
	Deadline time.Time

	// MaxRequests is the total number of packets the group may write,
	// including every retransmission. Each actual send atomically acquires
	// one unit before writing. Zero means unlimited.
	MaxRequests int64

	// Mode selects retransmitting or single-send behavior.
	Mode ProbeMode

	// MaxAttempts bounds the sends of a single ProbeRetry probe (the initial
	// request plus retransmissions). It is ignored in ProbeNoRetry mode,
	// where every probe sends exactly one request. Defaults to
	// defaultMaxAttempts.
	MaxAttempts int32

	// RTO is the base retransmission interval. The timeout after attempt n
	// (zero based) is (n+1)*RTO, matching Client. Defaults to defaultRTO.
	RTO time.Duration

	// Integrity, when set, is verified against every response that carries
	// MESSAGE-INTEGRITY. A response whose attribute fails verification is
	// dropped and can never produce a success ProbeResult.
	Integrity MessageIntegrity

	// RequireFingerprint drops responses that do not carry a valid
	// FINGERPRINT attribute.
	RequireFingerprint bool

	// LoggerFactory supplies the logger used for dropped or rejected
	// messages. A nil factory disables logging.
	LoggerFactory logging.LoggerFactory
}

// ProbeGroup schedules a scoped set of STUN probes. All probes of a group
// share one deadline and one total request budget, are demultiplexed by a
// single read loop over the group connection, and own their transaction IDs
// until they reach a terminal state.
//
// ProbeGroup is an independent scheduler and does not change the existing
// Client; both can be used on different connections.
type ProbeGroup struct {
	conn      Connection
	packet    net.PacketConn  // nil for stream transports
	ctx       context.Context //nolint:containedctx // group lifetime scope
	cancel    context.CancelFunc
	deadline  time.Time
	hasDDL    bool
	mode      ProbeMode
	maxAtt    int32
	rto       time.Duration
	integrity MessageIntegrity
	requireFP bool
	logger    logging.LeveledLogger

	// requestsLeft counts packets still writable by the whole group. A
	// negative value means unlimited. All sends acquire through
	// acquireBudget so concurrent retransmissions cannot amplify the budget.
	requestsLeft atomic.Int64

	mux     sync.Mutex
	waiters map[transactionID]*probeWaiter
	closed  bool

	closeCh  chan struct{}
	closeOne sync.Once
	wg       sync.WaitGroup
}

// probeWaiter is the per-probe state. It is registered before the first send
// and unregistered exactly once when the probe reaches a terminal state.
type probeWaiter struct {
	id     transactionID
	target net.Addr // expected source, nil on stream transports
	raw    []byte   // encoded request, reused for retransmissions
	done   chan ProbeResult

	// terminal guarantees a single ProbeResult per probe and makes late
	// responses or timeouts after completion harmless.
	terminal atomic.Bool
}

// deliver reports exactly one terminal result. Events arriving after the
// first terminal event are ignored.
func (w *probeWaiter) deliver(result ProbeResult) {
	if w.terminal.CompareAndSwap(false, true) {
		w.done <- result
	}
}

// NewProbeGroup creates a probe group and starts its single read loop. Call
// Close to terminate every pending probe and release the loop; Close also
// closes the underlying connection.
func NewProbeGroup(config ProbeConfig) (*ProbeGroup, error) { //nolint:cyclop
	if config.Conn == nil {
		return nil, ErrNoConnection
	}
	if config.MaxAttempts < 0 || config.MaxRequests < 0 {
		return nil, fmt.Errorf("%w: attempts and request budget must not be negative", ErrProbeConfig)
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = defaultMaxAttempts
	}
	if config.RTO <= 0 {
		config.RTO = defaultRTO
	}

	group := newProbeGroup(config)
	group.wg.Add(1)
	go group.readUntilClosed()

	return group, nil
}

func newProbeGroup(config ProbeConfig) *ProbeGroup {
	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}
	// WithCancel (or WithDeadline when a group deadline is set) owns the
	// cancel func stored on the group; Close invokes it, so the deadline
	// timer is released on either path.
	var cancel context.CancelFunc
	if !config.Deadline.IsZero() {
		ctx, cancel = context.WithDeadline(ctx, config.Deadline)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	group := &ProbeGroup{
		conn:      config.Conn,
		ctx:       ctx,
		cancel:    cancel,
		deadline:  config.Deadline,
		hasDDL:    !config.Deadline.IsZero(),
		mode:      config.Mode,
		maxAtt:    config.MaxAttempts,
		rto:       config.RTO,
		integrity: config.Integrity,
		requireFP: config.RequireFingerprint,
		waiters:   make(map[transactionID]*probeWaiter),
		closeCh:   make(chan struct{}),
	}
	// Zero means unlimited; represented as -1 for the CAS loop below.
	group.requestsLeft.Store(-1)
	if config.MaxRequests > 0 {
		group.requestsLeft.Store(config.MaxRequests)
	}
	if pc, ok := config.Conn.(net.PacketConn); ok {
		group.packet = pc
	}
	if config.LoggerFactory != nil {
		group.logger = config.LoggerFactory.NewLogger("stun")
	}

	return group
}

// Probe sends request and blocks until the probe reaches its single terminal
// ProbeResult. It is safe to call concurrently from multiple goroutines.
//
// On packet transports target selects the destination and the only accepted
// response source; it must be non-nil. On stream transports target must be
// nil and the peer is fixed by the connection.
//
// The request message is never modified: a missing transaction ID is
// generated on a private copy, and the encoded bytes are cloned before the
// first send.
func (g *ProbeGroup) Probe(request *Message, target net.Addr) ProbeResult {
	waiter, err := g.prepare(request, target)
	if err != nil {
		return ProbeResult{
			TransactionID: transactionIDOf(request),
			Error:         err,
		}
	}

	if err := g.send(waiter, 0); err != nil {
		g.terminate(waiter, ProbeResult{
			TransactionID: waiter.id,
			Error:         err,
		})

		return <-waiter.done
	}

	if g.mode == ProbeNoRetry {
		return g.awaitOnce(waiter)
	}

	return g.retryLoop(waiter)
}

func transactionIDOf(m *Message) (id [TransactionIDSize]byte) {
	if m != nil {
		return m.TransactionID
	}

	return id
}

func (g *ProbeGroup) prepare(request *Message, target net.Addr) (*probeWaiter, error) {
	if err := g.validateProbe(request, target); err != nil {
		return nil, err
	}
	msg, err := g.cloneRequest(request)
	if err != nil {
		return nil, err
	}

	waiter := &probeWaiter{
		id:     msg.TransactionID,
		target: target,
		raw:    append(make([]byte, 0, len(msg.Raw)), msg.Raw...),
		done:   make(chan ProbeResult, 1),
	}

	g.mux.Lock()
	defer g.mux.Unlock()
	if g.closed {
		return nil, ErrProbeGroupClosed
	}
	if _, exists := g.waiters[waiter.id]; exists {
		return nil, fmt.Errorf("%w: %x", ErrProbeTransactionID, waiter.id[:])
	}
	// The ID is reserved from this point until terminate() removes the
	// waiter, so no other probe can register or match it.
	g.waiters[waiter.id] = waiter

	return waiter, nil
}

func (g *ProbeGroup) validateProbe(request *Message, target net.Addr) error {
	if request == nil || request.Type != BindingRequest {
		return ErrProbeMessageType
	}
	if g.packet != nil && target == nil {
		return fmt.Errorf("%w: packet transport requires a target address", ErrProbeMessageType)
	}
	if g.packet == nil && target != nil {
		return fmt.Errorf("%w: per-message targets require a packet transport", ErrProbeMessageType)
	}

	return nil
}

func (g *ProbeGroup) cloneRequest(request *Message) (*Message, error) {
	msg := NewWithOptions(WithStrict(request.strict))
	if err := request.CloneTo(msg); err != nil {
		return nil, err
	}
	if msg.TransactionID == (transactionID{}) {
		msg.TransactionID = NewTransactionID()
		msg.WriteTransactionID()
	}
	if len(msg.Raw) == 0 {
		msg.Encode()
	}

	return msg, nil
}

// acquireBudget atomically reserves one packet. It runs immediately before
// every write, so the shared budget can never be amplified by concurrent
// initial sends or retransmissions.
func (g *ProbeGroup) acquireBudget() bool {
	for {
		left := g.requestsLeft.Load()
		if left < 0 {
			return true // unlimited
		}
		if left == 0 {
			return false
		}
		if g.requestsLeft.CompareAndSwap(left, left-1) {
			return true
		}
	}
}

// send writes one request, honoring context, group deadline and the shared
// packet budget. Retransmissions reuse waiter.raw and therefore the same
// transaction ID.
func (g *ProbeGroup) send(waiter *probeWaiter, attempt int32) error {
	if err := g.ctx.Err(); err != nil {
		return err
	}
	if g.isClosed() {
		return ErrProbeGroupClosed
	}
	if g.hasDDL && !time.Now().Before(g.deadline) {
		return context.DeadlineExceeded
	}
	if !g.acquireBudget() {
		return ErrProbeBudgetExhausted
	}

	var err error
	if g.packet != nil {
		_, err = g.packet.WriteTo(waiter.raw, waiter.target)
	} else {
		_, err = g.conn.Write(waiter.raw)
	}
	if err != nil {
		return err
	}
	if g.logger != nil {
		g.logger.Debugf("probe %x: sent attempt %d", waiter.id[:], attempt+1) //nolint:gosec
	}

	return nil
}

// awaitOnce waits for the single terminal event of a NoRetry probe.
func (g *ProbeGroup) awaitOnce(waiter *probeWaiter) ProbeResult {
	select {
	case result := <-waiter.done:
		return result
	case <-g.ctx.Done():
		g.terminate(waiter, ProbeResult{
			TransactionID: waiter.id,
			Error:         g.ctx.Err(),
		})

		return <-waiter.done
	case <-g.closeCh:
		g.terminate(waiter, ProbeResult{
			TransactionID: waiter.id,
			Error:         ErrProbeGroupClosed,
		})

		return <-waiter.done
	}
}

// retryLoop drives a Retry probe. Every iteration owns one timer that is
// stopped on every exit path, so no timer outlives the probe.
func (g *ProbeGroup) retryLoop(waiter *probeWaiter) ProbeResult {
	var attempt int32
	for {
		timer := time.NewTimer(g.backoff(attempt))
		select {
		case result := <-waiter.done:
			timer.Stop()

			return result
		case <-g.ctx.Done():
			timer.Stop()
			g.terminate(waiter, ProbeResult{
				TransactionID: waiter.id,
				Error:         g.ctx.Err(),
			})

			return <-waiter.done
		case <-g.closeCh:
			timer.Stop()
			g.terminate(waiter, ProbeResult{
				TransactionID: waiter.id,
				Error:         ErrProbeGroupClosed,
			})

			return <-waiter.done
		case <-timer.C:
		}

		// The read loop may have delivered a result concurrently with the
		// timer firing; the terminal guard settles the race.
		if waiter.terminal.Load() {
			return <-waiter.done
		}
		attempt++
		if attempt >= g.maxAtt {
			g.terminate(waiter, ProbeResult{
				TransactionID: waiter.id,
				Error:         ErrTransactionTimeOut,
			})

			return <-waiter.done
		}
		if err := g.send(waiter, attempt); err != nil {
			g.terminate(waiter, ProbeResult{
				TransactionID: waiter.id,
				Error:         err,
			})

			return <-waiter.done
		}
	}
}

// backoff returns the wait after attempt n before the next retransmission,
// clamped by the group deadline. Linear growth matches Client.
func (g *ProbeGroup) backoff(attempt int32) time.Duration {
	wait := time.Duration(attempt+1) * g.rto
	if !g.hasDDL {
		return wait
	}
	remaining := time.Until(g.deadline)
	if remaining < wait {
		if remaining <= 0 {
			return time.Nanosecond
		}

		return remaining
	}

	return wait
}

func (g *ProbeGroup) isClosed() bool {
	g.mux.Lock()
	defer g.mux.Unlock()

	return g.closed
}

// terminate unregisters the waiter and delivers its single terminal result.
// Removing the waiter first guarantees the transaction ID is released only
// after the probe ended and that a late response is dropped.
func (g *ProbeGroup) terminate(waiter *probeWaiter, result ProbeResult) {
	g.mux.Lock()
	delete(g.waiters, waiter.id)
	g.mux.Unlock()
	waiter.deliver(result)
}

// readUntilClosed demultiplexes every datagram or stream message to the
// matching active probe. Messages for unknown or finished transaction IDs are
// discarded, so a late response can never be associated with a later probe.
func (g *ProbeGroup) readUntilClosed() {
	defer g.wg.Done()
	const (
		initialBuffer = 1024
		maxBuffer     = 65535
	)
	buf := make([]byte, initialBuffer)
	for {
		if g.stopping() {
			return
		}
		n, source, err := g.readOne(buf)
		if err != nil {
			g.handleReadError(err)

			return
		}
		if n == 0 {
			continue
		}
		if n == len(buf) && len(buf) < maxBuffer {
			// Possibly truncated datagram: grow and rely on retransmission.
			buf = make([]byte, maxBuffer)
		}
		// Each packet gets a private backing array; the delivered Message
		// keeps referencing it after the loop reuses buf.
		g.processPacket(append([]byte(nil), buf[:n]...), source)
	}
}

func (g *ProbeGroup) stopping() bool {
	select {
	case <-g.closeCh:
		return true
	case <-g.ctx.Done():
		return true
	default:
		return false
	}
}

// handleReadError turns an unexpected read error into terminal results for
// every pending probe, so none can block on a dead transport. Errors caused by
// shutdown need no action because the probes are already being canceled.
func (g *ProbeGroup) handleReadError(err error) {
	if g.isClosed() || g.ctx.Err() != nil {
		return
	}
	g.failAll(err)
}

func (g *ProbeGroup) readOne(buf []byte) (int, net.Addr, error) {
	if g.packet != nil {
		return g.packet.ReadFrom(buf)
	}
	n, err := g.conn.Read(buf)

	return n, nil, err
}

// failAll terminates every pending probe with err.
func (g *ProbeGroup) failAll(err error) {
	g.mux.Lock()
	pending := make([]*probeWaiter, 0, len(g.waiters))
	for id, waiter := range g.waiters {
		delete(g.waiters, id)
		pending = append(pending, waiter)
	}
	g.mux.Unlock()
	for _, waiter := range pending {
		waiter.deliver(ProbeResult{
			TransactionID: waiter.id,
			Error:         err,
		})
	}
}

// processPacket validates and routes one received message. Every rejection
// path drops the packet (with an optional debug log); invalid or untrusted
// messages never reach a success event.
func (g *ProbeGroup) processPacket(data []byte, source net.Addr) { //nolint:cyclop
	msg := New()
	msg.Raw = data
	if err := msg.Decode(); err != nil {
		g.drop("decode failure", source)

		return
	}
	waiter, ok := g.matchWaiter(msg, source)
	if !ok {
		return
	}
	if !g.authentic(msg, source) {
		return
	}

	g.terminate(waiter, ProbeResult{
		TransactionID: waiter.id,
		Response:      msg,
		Source:        source,
	})
}

// matchWaiter enforces the transaction, message type and trusted-source
// checks. It returns false (and drops the packet) on any mismatch.
func (g *ProbeGroup) matchWaiter(msg *Message, source net.Addr) (*probeWaiter, bool) {
	// Match the transaction method and the response message class. Requests,
	// indications and other methods cannot complete a Binding probe.
	if msg.Type.Method != MethodBinding ||
		(msg.Type.Class != ClassSuccessResponse && msg.Type.Class != ClassErrorResponse) {
		g.drop("unexpected message type", source)

		return nil, false
	}
	waiter := g.lookupWaiter(msg.TransactionID)
	if waiter == nil {
		// No active probe: either a genuine late response or an ID this group
		// never used. Dropping it keeps reused IDs safe.
		g.drop("no matching transaction", source)

		return nil, false
	}
	// Trusted source check applies to packet transports.
	if waiter.target != nil && (source == nil || !sameAddress(source, waiter.target)) {
		g.drop("untrusted source address", source)

		return nil, false
	}

	return waiter, true
}

// authentic verifies FINGERPRINT and MESSAGE-INTEGRITY before a response is
// allowed to complete a probe.
func (g *ProbeGroup) authentic(msg *Message, source net.Addr) bool {
	if g.requireFP && Fingerprint.Check(msg) != nil {
		g.drop("missing or invalid fingerprint", source)

		return false
	}
	// A failed integrity check drops the message instead of surfacing it as a
	// success event.
	if g.integrity != nil && msg.Contains(AttrMessageIntegrity) && g.integrity.Check(msg) != nil {
		g.drop("message-integrity check failed", source)

		return false
	}

	return true
}

func (g *ProbeGroup) lookupWaiter(id transactionID) *probeWaiter {
	g.mux.Lock()
	defer g.mux.Unlock()

	return g.waiters[id]
}

func sameAddress(a, b net.Addr) bool {
	return a.Network() == b.Network() && a.String() == b.String()
}

func (g *ProbeGroup) drop(reason string, source net.Addr) {
	if g.logger != nil {
		g.logger.Debugf("probe group dropped message from %v: %s", source, reason)
	}
}

// Close terminates all pending probes, cancels the group context, stops the
// read loop and closes the underlying connection. It is idempotent and is
// the group's single terminal transition.
func (g *ProbeGroup) Close() error {
	var connErr error
	g.closeOne.Do(func() {
		g.mux.Lock()
		g.closed = true
		pending := make([]*probeWaiter, 0, len(g.waiters))
		for id, waiter := range g.waiters {
			delete(g.waiters, id)
			pending = append(pending, waiter)
		}
		g.mux.Unlock()

		// Unblock every probe whose result has not been produced yet. A probe
		// that terminated concurrently is already marked terminal, so deliver
		// is a no-op for it.
		for _, waiter := range pending {
			waiter.deliver(ProbeResult{
				TransactionID: waiter.id,
				Error:         ErrProbeGroupClosed,
			})
		}
		close(g.closeCh)
		// Cancel the context and close the transport; the latter unblocks the
		// read loop, the former unblocks any send-side wait.
		g.cancel()
		connErr = g.conn.Close()
		g.wg.Wait()
	})

	return connErr
}
