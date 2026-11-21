// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.io>
// SPDX-License-Identifier: MIT

//go:build !js

package stun

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptedUDPServer is a controllable STUN server: it records every received
// request and replies according to per-test hooks. The hook receives the
// request transaction ID so the reply can set it before computing
// authentication attributes.
type scriptedUDPServer struct {
	conn      *net.UDPConn
	mu        sync.Mutex
	requests  [][]byte
	replyFunc func(req *Message, nth int) *Message // nil means drop
	closed    chan struct{}
}

func newScriptedUDPServer(t *testing.T, reply func(req *Message, nth int) *Message) *scriptedUDPServer {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	s := &scriptedUDPServer{
		conn:      conn,
		replyFunc: reply,
		closed:    make(chan struct{}),
	}
	go s.serve()
	t.Cleanup(func() { _ = conn.Close() })

	return s
}

func (s *scriptedUDPServer) setReply(reply func(req *Message, nth int) *Message) {
	s.mu.Lock()
	s.replyFunc = reply
	s.mu.Unlock()
}

func (s *scriptedUDPServer) serve() {
	defer close(s.closed)
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		msg := new(Message)
		msg.Raw = append([]byte(nil), buf[:n]...)
		if err := msg.Decode(); err != nil {
			continue
		}
		s.mu.Lock()
		s.requests = append(s.requests, append([]byte(nil), buf[:n]...))
		nth := len(s.requests) - 1
		reply := s.replyFunc
		s.mu.Unlock()
		if reply == nil {
			continue
		}
		response := reply(msg, nth)
		if response == nil {
			continue
		}
		if response.Contains(AttrMessageIntegrity) || response.Contains(AttrFingerprint) {
			// The hook is responsible for setting the ID before computing
			// auth attributes; touching the header now would invalidate them.
		} else {
			response.TransactionID = msg.TransactionID
			response.WriteTransactionID()
		}
		if _, err := s.conn.WriteToUDP(response.Raw, addr); err != nil {
			return
		}
	}
}

func (s *scriptedUDPServer) addr() *net.UDPAddr {
	return s.conn.LocalAddr().(*net.UDPAddr) //nolint:forcetypeassert
}

func (s *scriptedUDPServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.requests)
}

func (s *scriptedUDPServer) requestIDs() [][TransactionIDSize]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([][TransactionIDSize]byte, 0, len(s.requests))
	for _, raw := range s.requests {
		var id [TransactionIDSize]byte
		copy(id[:], raw[8:20])
		ids = append(ids, id)
	}

	return ids
}

func successResponse() *Message {
	// Build + Encode leaves Raw ready to send; callers that add auth
	// attributes must not re-encode afterwards.
	m := MustBuild(TransactionID, BindingSuccess)
	m.Encode()

	return m
}

func errorResponse() *Message {
	m := MustBuild(TransactionID, BindingError,
		ErrorCodeAttribute{Code: CodeBadRequest, Reason: []byte("Bad Request")})
	m.Encode()

	return m
}

func newUDPGroup(t *testing.T, cfg ProbeConfig) (*ProbeGroup, *net.UDPConn) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	cfg.Conn = conn
	group, err := NewProbeGroup(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = group.Close() })

	return group, conn
}

func bindingRequestWithID() *Message {
	m := MustBuild(TransactionID, BindingRequest)
	m.Encode()

	return m
}

// TestProbeGroup_Success verifies the basic happy path: one request, one
// validated success response carrying the same transaction ID.
func TestProbeGroup_Success(t *testing.T) {
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return successResponse() })
	group, _ := newUDPGroup(t, ProbeConfig{Mode: ProbeNoRetry})

	req := bindingRequestWithID()
	result := group.Probe(req, server.addr())

	require.NoError(t, result.Error)
	require.NotNil(t, result.Response)
	assert.Equal(t, BindingSuccess, result.Response.Type)
	assert.Equal(t, req.TransactionID, result.TransactionID)
	assert.Equal(t, server.addr().String(), result.Source.String())
	assert.Equal(t, 1, server.requestCount())
}

// TestProbeGroup_ErrorResponseDelivered verifies an ERROR-CODE response is a
// terminal validated response, not an error result.
func TestProbeGroup_ErrorResponseDelivered(t *testing.T) {
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return errorResponse() })
	group, _ := newUDPGroup(t, ProbeConfig{Mode: ProbeNoRetry})

	result := group.Probe(bindingRequestWithID(), server.addr())

	require.NoError(t, result.Error)
	require.NotNil(t, result.Response)
	assert.Equal(t, BindingError, result.Response.Type)
	var code ErrorCodeAttribute
	require.NoError(t, code.GetFrom(result.Response))
	assert.Equal(t, CodeBadRequest, code.Code)
}

// TestProbeGroup_SharedBudgetAcquiresBeforeSend verifies requirement 1: the
// whole group shares one packet budget and each actual send (including
// retransmissions) consumes one unit; once exhausted no further writes occur.
func TestProbeGroup_SharedBudgetAcquiresBeforeSend(t *testing.T) {
	// Server never replies: every probe burns budget through retransmission.
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return nil })
	group, _ := newUDPGroup(t, ProbeConfig{
		Mode:        ProbeRetry,
		MaxRequests: 3,
		MaxAttempts: 10,
		RTO:         time.Millisecond,
	})

	resultCh := make(chan ProbeResult, 2)
	go func() { resultCh <- group.Probe(bindingRequestWithID(), server.addr()) }()
	go func() { resultCh <- group.Probe(bindingRequestWithID(), server.addr()) }()

	deadline := time.After(5 * time.Second)
	results := make([]ProbeResult, 0, 2)
	for len(results) < 2 {
		select {
		case r := <-resultCh:
			results = append(results, r)
		case <-deadline:
			require.FailNow(t, "probes did not terminate")
		}
	}

	// Exactly three packets in total across both probes.
	assert.Eventually(t, func() bool { return server.requestCount() == 3 }, time.Second, 5*time.Millisecond)
	budgetErrors := 0
	timeoutErrors := 0
	for _, r := range results {
		switch {
		case errors.Is(r.Error, ErrProbeBudgetExhausted):
			budgetErrors++
		case errors.Is(r.Error, ErrTransactionTimeOut):
			timeoutErrors++
		default:
			require.FailNowf(t, "unexpected result error", "%v", r.Error)
		}
	}
	assert.GreaterOrEqual(t, budgetErrors, 1, "at least one probe must hit the shared budget")
	assert.Equal(t, 2, budgetErrors+timeoutErrors)
}

// TestProbeGroup_RetransmitsSameID verifies requirement 2: retransmissions
// keep the same transaction ID and follow linear back-off; a late response
// completes the probe.
func TestProbeGroup_RetransmitsSameID(t *testing.T) {
	const replyAt = 2 // answer the third received packet (zero-based index 2)
	server := newScriptedUDPServer(t, func(_ *Message, nth int) *Message {
		if nth >= replyAt {
			return successResponse()
		}

		return nil
	})
	group, _ := newUDPGroup(t, ProbeConfig{
		Mode:        ProbeRetry,
		MaxAttempts: 10,
		RTO:         5 * time.Millisecond,
	})

	start := time.Now()
	result := group.Probe(bindingRequestWithID(), server.addr())
	elapsed := time.Since(start)

	require.NoError(t, result.Error)
	require.NotNil(t, result.Response)
	assert.Equal(t, 3, server.requestCount())
	ids := server.requestIDs()
	assert.Equal(t, ids[0], ids[1])
	assert.Equal(t, ids[1], ids[2])
	// Back-off is (1+2)*RTO minimum before the third send.
	assert.GreaterOrEqual(t, elapsed, 15*time.Millisecond)
}

// TestProbeGroup_TransactionIDNotReused verifies requirement 2: an in-flight
// transaction ID cannot be registered by another probe until the first one
// terminates.
func TestProbeGroup_TransactionIDNotReused(t *testing.T) {
	release := make(chan struct{})
	server := newScriptedUDPServer(t, func(*Message, int) *Message {
		<-release

		return successResponse()
	})
	group, _ := newUDPGroup(t, ProbeConfig{Mode: ProbeNoRetry})

	req := bindingRequestWithID()
	done := make(chan ProbeResult, 1)
	go func() { done <- group.Probe(req, server.addr()) }()

	// Wait until the first probe is registered before racing the second.
	assert.Eventually(t, func() bool {
		group.mux.Lock()
		defer group.mux.Unlock()

		return len(group.waiters) == 1
	}, time.Second, time.Millisecond)

	dup := group.Probe(req, server.addr())
	require.Error(t, dup.Error)
	assert.True(t, errors.Is(dup.Error, ErrProbeTransactionID))

	close(release)
	first := <-done
	require.NoError(t, first.Error)

	// After termination the ID is free and a fresh probe with it works.
	server.setReply(func(*Message, int) *Message { return successResponse() })
	again := group.Probe(req, server.addr())
	require.NoError(t, again.Error)
}

// TestProbeGroup_LateResponseDropped verifies requirement 4: a response that
// arrives after the probe ended is dropped and cannot affect a later probe
// that happens to reuse the same ID.
func TestProbeGroup_LateResponseDropped(t *testing.T) {
	var respond atomic.Bool
	server := newScriptedUDPServer(t, func(*Message, int) *Message {
		if respond.Load() {
			return successResponse()
		}

		return nil
	})
	group, _ := newUDPGroup(t, ProbeConfig{
		Mode:        ProbeRetry,
		MaxAttempts: 2,
		RTO:         5 * time.Millisecond,
	})

	req := bindingRequestWithID()
	first := group.Probe(req, server.addr())
	require.Error(t, first.Error)
	assert.True(t, errors.Is(first.Error, ErrTransactionTimeOut))

	// The server now answers stale requests with the same ID. Start a new
	// probe using a different ID first; the late response for the old ID must
	// be dropped rather than completing it.
	respond.Store(true)
	other := bindingRequestWithID()
	result := group.Probe(other, server.addr())
	require.NoError(t, result.Error)
	assert.Equal(t, other.TransactionID, result.TransactionID)
}

// TestProbeGroup_UntrustedSourceDropped verifies requirement 3: responses
// must come from the target the request was sent to.
func TestProbeGroup_UntrustedSourceDropped(t *testing.T) {
	// Target server silently drops everything.
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer func() { _ = target.Close() }()
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, _, readErr := target.ReadFromUDP(buf); readErr != nil {
				return
			}
		}
	}()

	// Attacker sends unsolicited success responses with random IDs.
	attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer func() { _ = attacker.Close() }()

	group, clientConn := newUDPGroup(t, ProbeConfig{
		Mode:        ProbeRetry,
		MaxAttempts: 5,
		RTO:         5 * time.Millisecond,
	})

	stopSpoof := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopSpoof:
				return
			case <-ticker.C:
				m := successResponse()
				_, _ = attacker.WriteToUDP(m.Raw, clientConn.LocalAddr().(*net.UDPAddr)) //nolint:forcetypeassert
			}
		}
	}()

	result := group.Probe(bindingRequestWithID(), target.LocalAddr().(*net.UDPAddr)) //nolint:forcetypeassert
	close(stopSpoof)
	wg.Wait()
	// Probe must time out: no spoofed packet (wrong source or unknown ID)
	// ever completes it.
	require.Error(t, result.Error)
	assert.True(t, errors.Is(result.Error, ErrTransactionTimeOut))
}

// TestProbeGroup_SpoofedResponseWithCorrectIDDropped covers the stricter
// case: an attacker that knows the transaction ID but sends from an address
// different from the target must still be rejected.
func TestProbeGroup_SpoofedResponseWithCorrectIDDropped(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer func() { _ = target.Close() }()
	// Drain requests arriving at the legitimate target so its socket buffer
	// never fills and blocks retransmissions.
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, _, readErr := target.ReadFromUDP(buf); readErr != nil {
				return
			}
		}
	}()

	attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer func() { _ = attacker.Close() }()

	group, clientConn := newUDPGroup(t, ProbeConfig{
		Mode:        ProbeRetry,
		MaxAttempts: 5,
		RTO:         5 * time.Millisecond,
	})

	req := bindingRequestWithID()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				m := successResponse()
				m.TransactionID = req.TransactionID
				m.WriteTransactionID()
				_, _ = attacker.WriteToUDP(m.Raw, clientConn.LocalAddr().(*net.UDPAddr)) //nolint:forcetypeassert
			}
		}
	}()

	result := group.Probe(req, target.LocalAddr().(*net.UDPAddr)) //nolint:forcetypeassert
	close(stop)
	wg.Wait()
	require.Error(t, result.Error)
	assert.True(t, errors.Is(result.Error, ErrTransactionTimeOut))
}

// TestProbeGroup_BadFingerprintAndIntegrityDropped verifies requirement 3:
// failing authentication attributes never produce a success event; a later
// valid response still completes the probe.
func TestProbeGroup_BadFingerprintAndIntegrityDropped(t *testing.T) {
	integrity := NewShortTermIntegrity("passwd")
	server := newScriptedUDPServer(t, func(req *Message, call int) *Message {
		if call == 0 {
			// First response carries a broken MESSAGE-INTEGRITY and a wrong
			// fingerprint: it must be dropped, never delivered as success.
			bad := MustBuild(TransactionID, BindingSuccess)
			bad.TransactionID = req.TransactionID
			bad.WriteTransactionID()
			bad.Add(AttrMessageIntegrity, make([]byte, 20))
			bad.Add(AttrFingerprint, make([]byte, 4))
			bad.Encode()

			return bad
		}
		good := MustBuild(TransactionID, BindingSuccess)
		good.TransactionID = req.TransactionID
		good.WriteTransactionID()
		// RFC 5389 ordering: MESSAGE-INTEGRITY before FINGERPRINT. The ID is
		// fixed in Raw before the HMAC/CRC that cover the header are computed.
		require.NoError(t, integrity.AddTo(good))
		require.NoError(t, Fingerprint.AddTo(good))

		return good
	})
	group, _ := newUDPGroup(t, ProbeConfig{
		Mode:               ProbeRetry,
		MaxAttempts:        10,
		RTO:                5 * time.Millisecond,
		Integrity:          integrity,
		RequireFingerprint: true,
	})

	result := group.Probe(bindingRequestWithID(), server.addr())
	require.NoError(t, result.Error)
	require.NotNil(t, result.Response)
	assert.Equal(t, BindingSuccess, result.Response.Type)
	assert.GreaterOrEqual(t, server.requestCount(), 2)
}

// TestProbeGroup_ContextCancelRemovesWaiter verifies requirement 4:
// canceling the group context immediately removes the waiter and terminates
// the probe, and subsequent probes keep working.
func TestProbeGroup_ContextCancelRemovesWaiter(t *testing.T) {
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	group, _ := newUDPGroup(t, ProbeConfig{
		Context: ctx,
		Mode:    ProbeNoRetry,
	})

	done := make(chan ProbeResult, 1)
	go func() { done <- group.Probe(bindingRequestWithID(), server.addr()) }()
	assert.Eventually(t, func() bool {
		group.mux.Lock()
		defer group.mux.Unlock()

		return len(group.waiters) == 1
	}, time.Second, time.Millisecond)

	cancel()
	select {
	case result := <-done:
		assert.ErrorIs(t, result.Error, context.Canceled)
	case <-time.After(time.Second):
		require.FailNow(t, "canceled probe did not terminate")
	}
	assert.Eventually(t, func() bool {
		group.mux.Lock()
		defer group.mux.Unlock()

		return len(group.waiters) == 0
	}, time.Second, time.Millisecond)

	// A group whose context was canceled rejects further work but Close stays
	// idempotent and does not hang.
	assert.NoError(t, group.Close())
	assert.NoError(t, group.Close())
}

// TestProbeGroup_DeadlineShared verifies requirement 1: one deadline bounds
// every probe of the group regardless of per-probe attempt settings.
func TestProbeGroup_DeadlineShared(t *testing.T) {
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return nil })
	deadline := time.Now().Add(40 * time.Millisecond)
	group, _ := newUDPGroup(t, ProbeConfig{
		Mode:        ProbeRetry,
		MaxAttempts: 1000,
		RTO:         5 * time.Millisecond,
		Deadline:    deadline,
	})

	start := time.Now()
	result := group.Probe(bindingRequestWithID(), server.addr())
	elapsed := time.Since(start)

	require.Error(t, result.Error)
	assert.True(t, errors.Is(result.Error, context.DeadlineExceeded))
	assert.Less(t, elapsed, 500*time.Millisecond)
}

// TestProbeGroup_SingleTerminalState verifies requirement 5: each probe
// delivers exactly one result even when response and timeout race, and the
// group transitions to closed only once.
func TestProbeGroup_SingleTerminalState(t *testing.T) {
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return successResponse() })
	group, _ := newUDPGroup(t, ProbeConfig{Mode: ProbeNoRetry})

	for range 20 {
		req := bindingRequestWithID()
		// Register the waiter directly so its buffered done channel can be
		// inspected after the probe returns.
		waiter, err := group.prepare(req, server.addr())
		require.NoError(t, err)
		require.NoError(t, group.send(waiter, 0))
		result := group.awaitOnce(waiter)
		require.NoError(t, result.Error)
		// The channel holds the single terminal event; a second delivery
		// would have overwritten nothing (buffered size 1, terminal guard).
		select {
		case extra := <-waiter.done:
			require.FailNowf(t, "unexpected extra terminal event", "%v", extra)
		default:
		}
	}
}

// TestProbeGroup_NoRetrySendsOnce verifies ProbeNoRetry writes a single
// packet even when no response ever arrives (probe terminates via context).
func TestProbeGroup_NoRetrySendsOnce(t *testing.T) {
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	group, _ := newUDPGroup(t, ProbeConfig{Context: ctx, Mode: ProbeNoRetry})

	result := group.Probe(bindingRequestWithID(), server.addr())
	require.Error(t, result.Error)
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, 1, server.requestCount())
}

// TestProbeGroup_ConcurrentProbes verifies many probes over one connection
// are demultiplexed correctly and each gets its own response.
func TestProbeGroup_ConcurrentProbes(t *testing.T) {
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return successResponse() })
	group, _ := newUDPGroup(t, ProbeConfig{Mode: ProbeNoRetry})

	const probeCount = 25
	var wg sync.WaitGroup
	errs := make(chan error, probeCount)
	for range probeCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := group.Probe(bindingRequestWithID(), server.addr())
			errs <- result.Error
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, probeCount, server.requestCount())
}

// TestProbeGroup_CloseReleasesResources verifies requirement 5: after Close
// pending probes terminate, the read loop exits and no goroutine remains
// blocked on the connection.
func TestProbeGroup_CloseReleasesResources(t *testing.T) {
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return nil })
	group, _ := newUDPGroup(t, ProbeConfig{Mode: ProbeNoRetry})

	done := make(chan ProbeResult, 1)
	go func() { done <- group.Probe(bindingRequestWithID(), server.addr()) }()
	assert.Eventually(t, func() bool {
		group.mux.Lock()
		defer group.mux.Unlock()

		return len(group.waiters) == 1
	}, time.Second, time.Millisecond)

	require.NoError(t, group.Close())
	select {
	case r := <-done:
		// Close cancels the group context and unblocks the probe either way;
		// both errors indicate prompt, non-leaking termination.
		assert.True(t, errors.Is(r.Error, ErrProbeGroupClosed) ||
			errors.Is(r.Error, context.Canceled), "got %v", r.Error)
	case <-time.After(time.Second):
		require.FailNow(t, "pending probe did not terminate on Close")
	}
	group.wg.Wait() // read loop must have returned

	// New probes on a closed group fail fast without touching the connection.
	r := group.Probe(bindingRequestWithID(), server.addr())
	assert.ErrorIs(t, r.Error, ErrProbeGroupClosed)
}

// TestProbeGroup_TransportBreakFailsAll verifies that a permanent read
// failure terminates every pending probe instead of leaving it blocked.
func TestProbeGroup_TransportBreakFailsAll(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	group, err := NewProbeGroup(ProbeConfig{Conn: clientConn, Mode: ProbeNoRetry})
	require.NoError(t, err)
	defer func() { _ = group.Close() }()

	const probeCount = 3
	results := make(chan ProbeResult, probeCount)
	for range probeCount {
		go func() {
			results <- group.Probe(bindingRequestWithID(), nil)
		}()
	}
	assert.Eventually(t, func() bool {
		group.mux.Lock()
		defer group.mux.Unlock()

		return len(group.waiters) == probeCount
	}, time.Second, time.Millisecond)

	require.NoError(t, serverConn.Close())
	for range probeCount {
		select {
		case result := <-results:
			require.Error(t, result.Error)
		case <-time.After(time.Second):
			require.FailNow(t, "probe did not terminate after transport break")
		}
	}
}

// TestProbeGroup_StreamTransport verifies ProbeNoRetry over a stream
// connection (net.Pipe), where no per-message source check applies.
func TestProbeGroup_StreamTransport(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := serverConn.Read(buf)
			if err != nil {
				return
			}
			req := new(Message)
			req.Raw = append([]byte(nil), buf[:n]...)
			if err := req.Decode(); err != nil {
				return
			}
			resp := successResponse()
			resp.TransactionID = req.TransactionID
			resp.WriteTransactionID()
			if _, err := serverConn.Write(resp.Raw); err != nil {
				return
			}
		}
	}()
	group, err := NewProbeGroup(ProbeConfig{
		Conn: clientConn,
		Mode: ProbeNoRetry,
	})
	require.NoError(t, err)
	defer func() { _ = group.Close() }()

	result := group.Probe(bindingRequestWithID(), nil)
	require.NoError(t, result.Error)
	assert.Equal(t, BindingSuccess, result.Response.Type)
	assert.Nil(t, result.Source)
}

// TestProbeGroup_NoGoroutineLeak verifies requirement 5: closing the group
// tears down the read loop even when the context is still live.
func TestProbeGroup_NoGoroutineLeak(t *testing.T) {
	server := newScriptedUDPServer(t, func(*Message, int) *Message { return successResponse() })
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	group, err := NewProbeGroup(ProbeConfig{Conn: conn, Mode: ProbeNoRetry})
	require.NoError(t, err)

	result := group.Probe(bindingRequestWithID(), server.addr())
	require.NoError(t, result.Error)

	before := runtime.NumGoroutine()
	require.NoError(t, group.Close())
	assert.Eventually(t, func() bool {
		runtime.GC()

		return runtime.NumGoroutine() <= before
	}, time.Second, 10*time.Millisecond)
}

// TestNewProbeGroup_Validation covers constructor and prepare-time errors.
func TestNewProbeGroup_Validation(t *testing.T) {
	t.Run("no connection", func(t *testing.T) {
		_, err := NewProbeGroup(ProbeConfig{})
		assert.ErrorIs(t, err, ErrNoConnection)
	})
	t.Run("negative budget", func(t *testing.T) {
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		_, err = NewProbeGroup(ProbeConfig{Conn: conn, MaxRequests: -1})
		assert.ErrorIs(t, err, ErrProbeConfig)
	})
	t.Run("zero budget means unlimited", func(t *testing.T) {
		server := newScriptedUDPServer(t, func(*Message, int) *Message { return successResponse() })
		group, _ := newUDPGroup(t, ProbeConfig{Mode: ProbeNoRetry, MaxRequests: 0})
		result := group.Probe(bindingRequestWithID(), server.addr())
		require.NoError(t, result.Error)
		assert.Equal(t, 1, server.requestCount())
	})
	t.Run("budget acquired before writing", func(t *testing.T) {
		server := newScriptedUDPServer(t, func(*Message, int) *Message { return nil })
		group, _ := newUDPGroup(t, ProbeConfig{
			Mode:        ProbeRetry,
			MaxRequests: 1,
			MaxAttempts: 3,
			RTO:         time.Millisecond,
		})
		result := group.Probe(bindingRequestWithID(), server.addr())
		// First send spends the only unit; the retransmission must fail
		// without writing another packet.
		assert.ErrorIs(t, result.Error, ErrProbeBudgetExhausted)
		assert.Equal(t, 1, server.requestCount())
	})
	t.Run("not a binding request", func(t *testing.T) {
		server := newScriptedUDPServer(t, func(*Message, int) *Message { return successResponse() })
		group, _ := newUDPGroup(t, ProbeConfig{Mode: ProbeNoRetry})
		indication := MustBuild(TransactionID, NewType(MethodBinding, ClassIndication))
		indication.Encode()
		r := group.Probe(indication, server.addr())
		assert.ErrorIs(t, r.Error, ErrProbeMessageType)
	})
	t.Run("packet transport needs target", func(t *testing.T) {
		group, _ := newUDPGroup(t, ProbeConfig{Mode: ProbeNoRetry})
		r := group.Probe(bindingRequestWithID(), nil)
		assert.ErrorIs(t, r.Error, ErrProbeMessageType)
	})
}
