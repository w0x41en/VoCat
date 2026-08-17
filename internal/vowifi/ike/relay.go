package ike

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type sessionRelay struct {
	transport   datagramTransport
	suite       negotiatedSuite
	keys        ikeKeys
	spii        [8]byte
	spir        [8]byte
	deleteID    uint32
	childInSPI  uint32
	childOutSPI uint32
	natt        bool
	keepalive   time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	esp    chan []byte

	mu                   sync.Mutex
	lastErr              error
	lastPeerMessageID    uint32
	lastPeerResponse     []byte
	hasLastPeerMessageID bool
}

func newSessionRelay(
	transport datagramTransport,
	suite negotiatedSuite,
	keys ikeKeys,
	initiatorSPI [8]byte,
	responderSPI [8]byte,
	options ...any,
) *sessionRelay {
	deleteMessageID := uint32(0)
	childInSPI := uint32(0)
	childOutSPI := uint32(0)
	natt := false
	keepalive := 20 * time.Second
	// Keep the internal constructor source-compatible with both the pre-merge
	// call sites (NAT flag, keepalive) and the newer explicit-delete-ID form.
	switch len(options) {
	case 2:
		natt, _ = options[0].(bool)
		keepalive, _ = options[1].(time.Duration)
	case 3:
		switch value := options[0].(type) {
		case uint32:
			deleteMessageID = value
		case int:
			deleteMessageID = uint32(value)
		}
		natt, _ = options[1].(bool)
		keepalive, _ = options[2].(time.Duration)
	case 5:
		switch value := options[0].(type) {
		case uint32:
			deleteMessageID = value
		case int:
			deleteMessageID = uint32(value)
		}
		natt, _ = options[1].(bool)
		keepalive, _ = options[2].(time.Duration)
		switch value := options[3].(type) {
		case uint32:
			childInSPI = value
		case int:
			childInSPI = uint32(value)
		}
		switch value := options[4].(type) {
		case uint32:
			childOutSPI = value
		case int:
			childOutSPI = uint32(value)
		}
	}
	if keepalive <= 0 {
		keepalive = 20 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	relay := &sessionRelay{
		transport:   transport,
		suite:       suite,
		keys:        keys,
		spii:        initiatorSPI,
		spir:        responderSPI,
		deleteID:    deleteMessageID,
		childInSPI:  childInSPI,
		childOutSPI: childOutSPI,
		natt:        natt,
		keepalive:   keepalive,
		ctx:         ctx,
		cancel:      cancel,
		done:        make(chan struct{}),
		esp:         make(chan []byte, 64),
	}
	go relay.run()
	return relay
}

func (relay *sessionRelay) run() {
	defer close(relay.done)
	defer close(relay.esp)
	buffer := make([]byte, 65535)
	lastKeepalive := time.Now()
	for {
		if err := relay.ctx.Err(); err != nil {
			return
		}
		n, isIKE, err := relay.transport.ReceiveSessionPacket(relay.ctx, buffer)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				if relay.natt && time.Since(lastKeepalive) >= relay.keepalive {
					if sendErr := relay.transport.SendSessionPacket(relay.ctx, []byte{0xff}, false); sendErr != nil {
						relay.fail(sendErr)
						return
					}
					lastKeepalive = time.Now()
				}
				continue
			}
			relay.fail(err)
			return
		}
		packet := append([]byte(nil), buffer[:n]...)
		if isIKE {
			if err := relay.handleIKE(packet); err != nil {
				if errors.Is(err, errMismatchedSessionSPIs) {
					// A reconnect can reuse the same NAT mapping while the ePDG still
					// has packets queued for the previous IKE SA. Those packets are
					// unrelated to this authenticated session and must be discarded;
					// treating one as fatal tears down the newly established CHILD_SA.
					continue
				}
				relay.fail(err)
				return
			}
			continue
		}
		if len(packet) == 1 && packet[0] == 0xff {
			// Peer NAT keepalive.
			continue
		}
		if len(packet) < 8 {
			// Unauthenticated network input must not tear down the session.
			continue
		}
		select {
		case relay.esp <- packet:
		default:
			// Keep the sole socket reader available for IKE/DPD if the
			// data-plane consumer falls behind.
		case <-relay.ctx.Done():
			return
		}
	}
}

var errMismatchedSessionSPIs = errors.New("ike: session packet has mismatched SPIs")

// Peer-requested teardown is a distinct runtime outcome from a local
// protocol/transport failure. Keep these sentinels stable so the orchestrator
// and logs can report an ePDG DELETE accurately.
var (
	ErrPeerDeletedIKESA   = errors.New("ike: peer deleted IKE SA")
	ErrPeerDeletedChildSA = errors.New("ike: peer deleted CHILD_SA")
	errPeerDeletedIKESA   = ErrPeerDeletedIKESA
	errPeerDeletedChildSA = ErrPeerDeletedChildSA
)

func (relay *sessionRelay) handleIKE(packet []byte) error {
	header, _, err := parseIKEPacket(packet)
	if err != nil {
		return err
	}
	if header.InitiatorSPI != relay.spii || header.ResponderSPI != relay.spir {
		return errMismatchedSessionSPIs
	}
	if header.Flags&flagResponse != 0 {
		return nil
	}
	if relay.hasLastPeerMessageID && header.MessageID == relay.lastPeerMessageID {
		// The peer owns an independent message-ID space. Retransmit the exact
		// encrypted response instead of running the request again.
		return relay.transport.SendSessionPacket(relay.ctx, relay.lastPeerResponse, true)
	}
	decryptedHeader, payloads, err := decryptPayloads(packet, relay.suite, relay.keys.SKer, relay.keys.SKar)
	if err != nil {
		return err
	}
	if header.Exchange == exchangeCreateChildSA {
		if err := relay.sendPeerResponse(decryptedHeader, []payload{makeNotify(notifyNoAdditionalSAs, nil)}); err != nil {
			return err
		}
		return nil
	}
	if header.Exchange != exchangeInformational {
		// RFC 7296 permits an endpoint to ignore a request it cannot process.
		// Do not kill a healthy SA just because an ePDG asks for an extension we
		// do not implement.
		return nil
	}

	deleteProtocol, deletePayload := classifyPeerDelete(payloads)
	var responsePayloads []payload
	if deleteProtocol == peerDeleteESP {
		responsePayloads = []payload{{Type: payloadDelete, Body: relay.espDeleteResponseBody(deletePayload)}}
	}
	if err := relay.sendPeerResponse(decryptedHeader, responsePayloads); err != nil {
		return err
	}
	switch deleteProtocol {
	case peerDeleteIKE:
		return errPeerDeletedIKESA
	case peerDeleteESP:
		return errPeerDeletedChildSA
	default:
		return nil
	}
}

// sendPeerResponse encrypts, sends, and caches one responder response. The
// cache is populated only after the socket accepted the packet so a
// retransmission can safely replay the exact bytes.
func (relay *sessionRelay) sendPeerResponse(header ikeHeader, payloads []payload) error {
	response, err := encryptPayloads(ikeHeader{
		InitiatorSPI: relay.spii,
		ResponderSPI: relay.spir,
		Exchange:     header.Exchange,
		Flags:        flagInitiator | flagResponse,
		MessageID:    header.MessageID,
	}, payloads, relay.suite, relay.keys.SKei, relay.keys.SKai, nil)
	if err != nil {
		return err
	}
	if err := relay.transport.SendSessionPacket(relay.ctx, response, true); err != nil {
		return err
	}
	relay.lastPeerMessageID = header.MessageID
	relay.lastPeerResponse = append(relay.lastPeerResponse[:0], response...)
	relay.hasLastPeerMessageID = true
	return nil
}

const (
	peerDeleteNone uint8 = iota
	peerDeleteIKE        = protocolIKE
	peerDeleteESP        = protocolESP
)

// classifyPeerDelete returns only well-formed IKE/ESP DELETE requests. A
// NOTIFY, an unknown payload, or a malformed DELETE still receives an empty
// INFORMATIONAL response and leaves the session alive.
func classifyPeerDelete(payloads []payload) (uint8, payload) {
	for _, item := range payloads {
		if item.Type != payloadDelete || len(item.Body) < 4 {
			continue
		}
		protocol := item.Body[0]
		spiSize := int(item.Body[1])
		count := int(binary.BigEndian.Uint16(item.Body[2:4]))
		if protocol == protocolIKE {
			if spiSize == 0 && count == 0 && len(item.Body) == 4 {
				return peerDeleteIKE, item
			}
			continue
		}
		if protocol == protocolESP && spiSize == 4 && count > 0 &&
			len(item.Body) == 4+spiSize*count {
			return peerDeleteESP, item
		}
	}
	return peerDeleteNone, payload{}
}

func (relay *sessionRelay) espDeleteResponseBody(request payload) []byte {
	spi := relay.childInSPI
	if spi == 0 && len(request.Body) >= 8 && request.Body[1] == 4 {
		// Keep source compatibility for older relay callers that did not pass
		// CHILD_SA SPIs: echo the requested SPI as a safe fallback.
		spi = binary.BigEndian.Uint32(request.Body[4:8])
	}
	body := []byte{protocolESP, 4, 0, 1, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(body[4:], spi)
	return body
}

func (relay *sessionRelay) fail(err error) {
	relay.mu.Lock()
	if relay.lastErr == nil {
		relay.lastErr = err
	}
	relay.mu.Unlock()
	relay.cancel()
}

func (relay *sessionRelay) SendESP(ctx context.Context, packet []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-relay.done:
		return relay.terminalError()
	default:
	}
	return relay.transport.SendSessionPacket(ctx, packet, false)
}

func (relay *sessionRelay) ReceiveESP(ctx context.Context, buffer []byte) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case packet, ok := <-relay.esp:
		if !ok {
			return 0, relay.terminalError()
		}
		if len(packet) > len(buffer) {
			return 0, errors.New("ike: ESP receive buffer is too small")
		}
		copy(buffer, packet)
		return len(packet), nil
	}
}

func (relay *sessionRelay) terminalError() error {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.lastErr != nil {
		return relay.lastErr
	}
	return net.ErrClosed
}

func (relay *sessionRelay) Close() error {
	relay.cancel()
	// ReceiveSessionPacket implementations normally observe the canceled
	// context through a short read deadline. Close the transport as an explicit
	// wake-up as well: a socket implementation that is stuck in Read must not
	// hold teardown (and the associated TUN interface) indefinitely.
	transportErr := relay.transport.Close()
	<-relay.done
	return errors.Join(relay.terminalErrorIfFailure(), transportErr)
}

func (relay *sessionRelay) CloseWithDelete(ctx context.Context) error {
	deleteErr := relay.sendIKEDelete(ctx)
	return errors.Join(deleteErr, relay.Close())
}

func (relay *sessionRelay) sendIKEDelete(ctx context.Context) error {
	return sendIKESADelete(ctx, relay.transport, relay.suite, relay.keys, relay.spii, relay.spir, relay.deleteID)
}

func sendIKESADelete(
	ctx context.Context,
	transport datagramTransport,
	suite negotiatedSuite,
	keys ikeKeys,
	initiatorSPI [8]byte,
	responderSPI [8]byte,
	messageID uint32,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		// Teardown is often called with the operation context already canceled.
		// Give the protocol-level release a short independent chance to leave.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		defer cancel()
	}
	request, err := encryptPayloads(ikeHeader{
		InitiatorSPI: initiatorSPI,
		ResponderSPI: responderSPI,
		Exchange:     exchangeInformational,
		Flags:        flagInitiator,
		MessageID:    messageID,
	}, []payload{{
		Type: payloadDelete,
		Body: []byte{protocolIKE, 0, 0, 0},
	}}, suite, keys.SKei, keys.SKai, nil)
	if err != nil {
		return fmt.Errorf("ike: build IKE SA delete: %w", err)
	}
	if err := transport.SendSessionPacket(ctx, request, true); err != nil {
		return fmt.Errorf("ike: send IKE SA delete: %w", err)
	}
	return nil
}

func (relay *sessionRelay) terminalErrorIfFailure() error {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return relay.lastErr
}

var _ NATTPacketRelay = (*sessionRelay)(nil)
