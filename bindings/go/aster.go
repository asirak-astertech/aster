// Package aster provides the first-class Go binding for the stable Aster C ABI.
package aster

/*
#cgo CFLAGS: -I${SRCDIR}/../c
#cgo LDFLAGS: -laster_ffi
#include <stdlib.h>
#include "aster_mesh.h"
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"unsafe"
)

// ProtocolVersion is the legacy name for the stable replication-wire version.
// It does not report the semantic version selected by an authenticated session.
func ProtocolVersion() uint16 {
	return uint16(C.aster_protocol_version())
}

// ReplicationWireVersion reports the stable wire/profile version.
func ReplicationWireVersion() uint16 {
	return uint16(C.aster_replication_wire_version())
}

// DefaultSemanticVersion reports the semantic version offered first by default.
func DefaultSemanticVersion() uint16 {
	return uint16(C.aster_default_semantic_version())
}

// HighestSupportedSemanticVersion reports this build's highest semantic version.
func HighestSupportedSemanticVersion() uint16 {
	return uint16(C.aster_highest_supported_semantic_version())
}

type DataClass uint32

const (
	State  DataClass = C.ASTER_STATE
	Event  DataClass = C.ASTER_EVENT
	Record DataClass = C.ASTER_RECORD
	Blob   DataClass = C.ASTER_BLOB
)

type Priority uint32

const (
	Routine     Priority = C.ASTER_ROUTINE
	PriorityMsg Priority = C.ASTER_PRIORITY
	Immediate   Priority = C.ASTER_IMMEDIATE
	Flash       Priority = C.ASTER_FLASH
)

type EmissionThreshold uint32

const (
	EmitRoutine   EmissionThreshold = C.ASTER_ROUTINE
	EmitPriority  EmissionThreshold = C.ASTER_PRIORITY
	EmitImmediate EmissionThreshold = C.ASTER_IMMEDIATE
	EmitFlash     EmissionThreshold = C.ASTER_FLASH
	ReceiveOnly   EmissionThreshold = C.ASTER_RECEIVE_ONLY
)

type Error struct {
	Status uint32
	Detail string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("Aster native status %d", e.Status)
}

type PublishOptions struct {
	LogicalKey []byte
	Priority   Priority
	TTLMillis  *uint64
	Tombstone  bool
}

type PublishReceipt struct {
	ItemID            [32]byte
	Publisher         [32]byte
	CausalCounter     uint64
	EventSequence     *uint64
	EffectivePriority Priority
}

// BatchPublicationPolicy selects whether compact retained items also keep a
// semantic-v1 singleton. The zero value is the offline-safe RetainedDual mode.
type BatchPublicationPolicy uint32

const (
	RetainedDual BatchPublicationPolicy = C.ASTER_BATCH_RETAINED_DUAL
	BatchOnly    BatchPublicationPolicy = C.ASTER_BATCH_ONLY
)

// BatchPublishItem is one member of a bounded, ordered atomic publication.
// Every member must use the same class, topic, and scope.
type BatchPublishItem struct {
	Class   DataClass
	Topic   string
	Scope   string
	Payload []byte
	Options PublishOptions
}

// BatchPublishResult preserves request order and reports the aggregate victims
// of the batch's single post-insert quota pass.
type BatchPublishResult struct {
	Items   []PublishReceipt
	Evicted [][32]byte
}

type BlobID [32]byte

type BlobOptions struct {
	Priority  Priority
	TTLMillis *uint64
	ChunkSize uint32
	MediaType string
	SchemaID  []byte
}

type BlobFinish struct {
	BlobID  BlobID
	Receipt PublishReceipt
}

type Query struct {
	Topic              string
	Scope              string
	LogicalKey         []byte
	Class              *DataClass
	IncludeDescendants bool
	IncludeRecoverable bool
	IncludeTombstones  bool
	Limit              uint64
}

type Item struct {
	ItemID        [32]byte
	Publisher     [32]byte
	Class         DataClass
	Priority      Priority
	CausalCounter uint64
	EventSequence *uint64
	Topic         string
	Scope         string // Compatibility alias for CurrentScope.
	OriginScope   string
	CurrentScope  string
	LogicalKey    []byte
	Payload       []byte
	Tombstone     bool
}

type Conflict struct {
	LogicalKey  []byte
	SiblingIDs  [][32]byte
	MergePolicy *string
}

type BridgeFilter struct {
	FromScope       string
	ToScope         string
	Topic           string
	MinimumPriority Priority
}

// PriorityMask is the explicit set of source-authenticated priorities an
// authority or local narrowing policy permits.
type PriorityMask uint8

const (
	AllowRoutine   PriorityMask = C.ASTER_PRIORITY_MASK_ROUTINE
	AllowPriority  PriorityMask = C.ASTER_PRIORITY_MASK_PRIORITY
	AllowImmediate PriorityMask = C.ASTER_PRIORITY_MASK_IMMEDIATE
	AllowFlash     PriorityMask = C.ASTER_PRIORITY_MASK_FLASH
	AllowAll       PriorityMask = C.ASTER_PRIORITY_MASK_ALL
)

type BridgeAuthorizationID [32]byte
type BridgeRouteHandle [32]byte

type BridgeAuthorizationPolicy struct {
	Topics            []string
	AllowedPriorities PriorityMask
	MaxTotalHops      uint8
}

type BridgeNarrowingPolicy struct {
	// Empty Topics retains every topic allowed by the signed authorization.
	Topics            []string
	AllowedPriorities PriorityMask
}

type BridgeAuthorizationResult struct {
	ID              BridgeAuthorizationID
	Generation      uint64
	ControlSequence uint64
	Enabled         bool
}

type BridgeCommitStatus uint32

const (
	BridgeActive            BridgeCommitStatus = C.ASTER_BRIDGE_ACTIVE
	BridgeRetainedAlternate BridgeCommitStatus = C.ASTER_BRIDGE_RETAINED_ALTERNATE
	BridgeDuplicateActive   BridgeCommitStatus = C.ASTER_BRIDGE_DUPLICATE_ACTIVE
	BridgeDuplicateInactive BridgeCommitStatus = C.ASTER_BRIDGE_DUPLICATE_INACTIVE
)

type BridgeRouteResult struct {
	Handle            BridgeRouteHandle
	SourceItem        [32]byte
	CurrentScope      string
	CurrentRouteEpoch uint64
	HopCount          uint8
	Status            BridgeCommitStatus
}

type BridgeAuthorizationStatus struct {
	ID                BridgeAuthorizationID
	Authority         [32]byte
	BridgeNode        [32]byte
	SourceScope       string
	TargetScope       string
	Generation        uint64
	ControlSequence   uint64
	Applied           bool
	Current           bool
	Enabled           bool
	Usable            bool
	SourceRouteEpoch  *uint64
	TargetRouteEpoch  *uint64
	Topics            []string
	AllowedPriorities PriorityMask
	MaxTotalHops      *uint8
}

type BridgeRouteStatus struct {
	Handle            BridgeRouteHandle
	SourceItem        [32]byte
	OriginScope       string
	OriginRouteEpoch  uint64
	CurrentScope      string
	CurrentRouteEpoch uint64
	Topic             string
	Priority          Priority
	HopCount          uint8
	Active            bool
	Live              bool
}

// RekeyAccess is an explicit fresh-epoch recipient mode. Zero is invalid.
type RekeyAccess uint32

const (
	RekeyRouteOnly  RekeyAccess = C.ASTER_REKEY_ROUTE_ONLY
	RekeyReadTopics RekeyAccess = C.ASTER_REKEY_READ_TOPICS
)

// RekeyRecipient contains only a node identity and high-level access choice.
// It never contains keys, provider state, or serialized control objects.
type RekeyRecipient struct {
	NodeID [32]byte
	Access RekeyAccess
	Topics []string
}

func RouteOnlyRecipient(nodeID [32]byte) RekeyRecipient {
	return RekeyRecipient{NodeID: nodeID, Access: RekeyRouteOnly}
}

func ReadTopicsRecipient(nodeID [32]byte, topics ...string) RekeyRecipient {
	return RekeyRecipient{NodeID: nodeID, Access: RekeyReadTopics, Topics: append([]string(nil), topics...)}
}

type ScopeRekeyReceipt struct {
	Epoch              uint64
	RegistryGeneration uint64
	RecipientCount     uint64
	ControlSequence    uint64
}

type PeerState uint32
type SyncState uint32

const (
	PeerOffline        PeerState = C.ASTER_PEER_OFFLINE
	PeerAuthenticating PeerState = C.ASTER_PEER_AUTHENTICATING
	PeerReady          PeerState = C.ASTER_PEER_READY
	PeerRejected       PeerState = C.ASTER_PEER_REJECTED
	PeerRevoked        PeerState = C.ASTER_PEER_REVOKED
	SyncIdle           SyncState = C.ASTER_SYNC_IDLE
	SyncReconciling    SyncState = C.ASTER_SYNC_RECONCILING
	SyncTransferring   SyncState = C.ASTER_SYNC_TRANSFERRING
	SyncConverged      SyncState = C.ASTER_SYNC_CONVERGED
	SyncSuspended      SyncState = C.ASTER_SYNC_SUSPENDED
)

type PeerSnapshot struct {
	Peer             [32]byte
	PeerState        PeerState
	SyncState        SyncState
	LastChangeMillis *uint64
	Detail           *string
}

type Delivery struct {
	Subscription uint64
	Attempt      uint64
	Item         Item
}

type Subscription struct {
	node *Node
	ID   uint64
}

type Node struct {
	mu     sync.Mutex
	handle C.aster_node_t
}

// BridgeEnrollment is a process-local move-only capability. EnableBridge
// consumes it once native authority processing starts, including error paths.
type BridgeEnrollment struct {
	mu     sync.Mutex
	handle C.aster_bridge_enrollment_t
}

// BlobWriter is a bounded, two-pass streaming writer. Finish durably finalizes
// encrypted chunks and idempotently publishes their authenticated manifest.
type BlobWriter struct {
	mu     sync.Mutex
	node   *Node
	handle C.aster_blob_writer_t
}

// BlobReader incrementally authenticates and returns Blob plaintext.
type BlobReader struct {
	mu     sync.Mutex
	node   *Node
	handle C.aster_blob_reader_t
}

func nativeBytes(value []byte) (C.aster_bytes_t, unsafe.Pointer) {
	if len(value) == 0 {
		return C.aster_bytes_t{}, nil
	}
	pointer := C.CBytes(value)
	return C.aster_bytes_t{data: (*C.uint8_t)(pointer), len: C.size_t(len(value))}, pointer
}

func nativeString(value string) (C.aster_bytes_t, unsafe.Pointer) {
	return nativeBytes([]byte(value))
}

func freePointers(values ...unsafe.Pointer) {
	for _, value := range values {
		if value != nil {
			C.free(value)
		}
	}
}

func ownedBytes(value C.aster_owned_buffer_t) []byte {
	if value.len == 0 {
		return []byte{}
	}
	return C.GoBytes(unsafe.Pointer(value.data), C.int(value.len))
}

func lastError() string {
	output := C.aster_owned_buffer_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_owned_buffer_t),
	}
	if C.aster_last_error(&output) != C.ASTER_OK {
		return "native error (diagnostic unavailable)"
	}
	detail := string(ownedBytes(output))
	C.aster_buffer_free(&output)
	return detail
}

func check(status C.aster_status_t) error {
	if status == C.ASTER_OK {
		return nil
	}
	return &Error{Status: uint32(status), Detail: lastError()}
}

func Open(storePath string, provisioningBundle []byte) (*Node, error) {
	var options C.aster_node_options_t
	if err := check(C.aster_node_options_init(&options)); err != nil {
		return nil, err
	}
	path, pathPointer := nativeString(storePath)
	bundle, bundlePointer := nativeBytes(provisioningBundle)
	defer freePointers(pathPointer, bundlePointer)
	options.store_path = path
	options.provisioning_bundle = bundle
	node := &Node{}
	if err := check(C.aster_node_open(&options, &node.handle)); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(node, func(value *Node) { _ = value.Close() })
	return node, nil
}

func (n *Node) active() error {
	if n.handle.value == 0 {
		return &Error{Status: C.ASTER_CLOSED, Detail: "node is closed"}
	}
	return nil
}

func (n *Node) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.handle.value == 0 {
		return nil
	}
	runtime.SetFinalizer(n, nil)
	return check(C.aster_node_close(&n.handle))
}

func (n *Node) Zeroize() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return err
	}
	runtime.SetFinalizer(n, nil)
	return check(C.aster_node_zeroize(&n.handle))
}

func receipt(value C.aster_publish_receipt_t) PublishReceipt {
	result := PublishReceipt{
		CausalCounter:     uint64(value.causal_counter),
		EffectivePriority: Priority(value.effective_priority),
	}
	for index := range 32 {
		result.ItemID[index] = byte(value.item_id[index])
		result.Publisher[index] = byte(value.publisher[index])
	}
	if value.has_event_sequence != 0 {
		sequence := uint64(value.event_sequence)
		result.EventSequence = &sequence
	}
	return result
}

func (n *Node) Publish(class DataClass, topic, scope string, payload []byte, options PublishOptions) (PublishReceipt, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return PublishReceipt{}, err
	}
	topicValue, topicPointer := nativeString(topic)
	scopeValue, scopePointer := nativeString(scope)
	keyValue, keyPointer := nativeBytes(options.LogicalKey)
	payloadValue, payloadPointer := nativeBytes(payload)
	defer freePointers(topicPointer, scopePointer, keyPointer, payloadPointer)
	request := C.aster_publish_request_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_publish_request_t),
		data_class:  C.aster_data_class_t(class),
		priority:    C.aster_priority_t(options.Priority),
		topic:       topicValue, scope: scopeValue, logical_key: keyValue, payload: payloadValue,
	}
	if options.TTLMillis != nil {
		request.has_ttl = 1
		request.ttl_ms = C.uint64_t(*options.TTLMillis)
	}
	if options.Tombstone {
		request.tombstone = 1
	}
	output := C.aster_publish_receipt_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_publish_receipt_t),
	}
	if err := check(C.aster_node_publish(n.handle, &request, &output)); err != nil {
		return PublishReceipt{}, err
	}
	return receipt(output), nil
}

// PublishBatch atomically commits 2-64 ordered non-Blob items. A rejected call
// commits no member and consumes no publisher counter or event sequence.
func (n *Node) PublishBatch(items []BatchPublishItem, policy BatchPublicationPolicy) (BatchPublishResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return BatchPublishResult{}, err
	}
	if len(items) < 2 || len(items) > 64 {
		return BatchPublishResult{}, fmt.Errorf("batch must contain between 2 and 64 items")
	}
	if policy != RetainedDual && policy != BatchOnly {
		return BatchPublishResult{}, fmt.Errorf("unknown batch publication policy %d", policy)
	}

	memory := C.calloc(C.size_t(len(items)), C.size_t(C.sizeof_aster_publish_request_t))
	if memory == nil {
		return BatchPublishResult{}, fmt.Errorf("allocate native batch items")
	}
	defer C.free(memory)
	nativeItems := unsafe.Slice((*C.aster_publish_request_t)(memory), len(items))
	allocations := make([]unsafe.Pointer, 0, len(items)*4)
	defer func() { freePointers(allocations...) }()
	for index, item := range items {
		topic, topicAllocation := nativeString(item.Topic)
		scope, scopeAllocation := nativeString(item.Scope)
		key, keyAllocation := nativeBytes(item.Options.LogicalKey)
		payload, payloadAllocation := nativeBytes(item.Payload)
		allocations = append(allocations, topicAllocation, scopeAllocation, keyAllocation, payloadAllocation)
		native := &nativeItems[index]
		native.abi_version = C.ASTER_ABI_VERSION
		native.struct_size = C.uint32_t(C.sizeof_aster_publish_request_t)
		native.data_class = C.aster_data_class_t(item.Class)
		native.priority = C.aster_priority_t(item.Options.Priority)
		native.topic = topic
		native.scope = scope
		native.logical_key = key
		native.payload = payload
		if item.Options.TTLMillis != nil {
			native.has_ttl = 1
			native.ttl_ms = C.uint64_t(*item.Options.TTLMillis)
		}
		if item.Options.Tombstone {
			native.tombstone = 1
		}
	}

	request := C.aster_publish_batch_request_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_publish_batch_request_t),
		items:       (*C.aster_publish_request_t)(memory),
		item_count:  C.size_t(len(items)),
		policy:      C.aster_batch_policy_t(policy),
	}
	var nativeResult C.aster_batch_result_t
	if err := check(C.aster_node_publish_batch(n.handle, &request, &nativeResult)); err != nil {
		return BatchPublishResult{}, err
	}
	return readBatchResult(nativeResult)
}

func readBatchResult(nativeResult C.aster_batch_result_t) (BatchPublishResult, error) {
	defer C.aster_batch_result_close(&nativeResult)

	var itemCount C.size_t
	if err := check(C.aster_batch_result_len(nativeResult, &itemCount)); err != nil {
		return BatchPublishResult{}, err
	}
	result := BatchPublishResult{Items: make([]PublishReceipt, 0, int(itemCount))}
	for index := C.size_t(0); index < itemCount; index++ {
		output := C.aster_publish_receipt_t{
			abi_version: C.ASTER_ABI_VERSION,
			struct_size: C.uint32_t(C.sizeof_aster_publish_receipt_t),
		}
		if err := check(C.aster_batch_result_get(nativeResult, index, &output)); err != nil {
			return BatchPublishResult{}, err
		}
		result.Items = append(result.Items, receipt(output))
	}

	var evictionCount C.size_t
	if err := check(C.aster_batch_result_evicted_len(nativeResult, &evictionCount)); err != nil {
		return BatchPublishResult{}, err
	}
	result.Evicted = make([][32]byte, 0, int(evictionCount))
	for index := C.size_t(0); index < evictionCount; index++ {
		output := C.aster_item_id_t{
			abi_version: C.ASTER_ABI_VERSION,
			struct_size: C.uint32_t(C.sizeof_aster_item_id_t),
		}
		if err := check(C.aster_batch_result_evicted_get(nativeResult, index, &output)); err != nil {
			return BatchPublishResult{}, err
		}
		var itemID [32]byte
		for byteIndex := range itemID {
			itemID[byteIndex] = byte(output.bytes[byteIndex])
		}
		result.Evicted = append(result.Evicted, itemID)
	}
	return result, nil
}

// RekeyScope durably publishes a fresh authority-managed scope epoch. Registry
// and nested topic memory are copied into C-owned call buffers and released as
// soon as the synchronous native call returns.
func (n *Node) RekeyScope(signedPublicRegistry []byte, minimumRegistryGeneration uint64,
	scope string, newEpoch uint64, recipients []RekeyRecipient) (ScopeRekeyReceipt, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return ScopeRekeyReceipt{}, err
	}
	if len(signedPublicRegistry) == 0 || len(signedPublicRegistry) > 16*1024*1024 {
		return ScopeRekeyReceipt{}, fmt.Errorf("signed public registry must be between 1 byte and 16 MiB")
	}
	if len(scope) == 0 || len([]byte(scope)) > 128 {
		return ScopeRekeyReceipt{}, fmt.Errorf("scope must be between 1 and 128 UTF-8 bytes")
	}
	if newEpoch == 0 {
		return ScopeRekeyReceipt{}, fmt.Errorf("new epoch must be nonzero")
	}
	if len(recipients) == 0 || len(recipients) > 128 {
		return ScopeRekeyReceipt{}, fmt.Errorf("rekey recipients must contain between 1 and 128 entries")
	}

	recipientMemory := C.calloc(C.size_t(len(recipients)), C.size_t(C.sizeof_aster_rekey_recipient_t))
	if recipientMemory == nil {
		return ScopeRekeyReceipt{}, fmt.Errorf("allocate native rekey recipients")
	}
	defer C.free(recipientMemory)
	nativeRecipients := unsafe.Slice((*C.aster_rekey_recipient_t)(recipientMemory), len(recipients))
	var nestedAllocations []unsafe.Pointer
	defer func() { freePointers(nestedAllocations...) }()

	for recipientIndex, recipient := range recipients {
		if recipient.Access == RekeyRouteOnly && len(recipient.Topics) != 0 {
			return ScopeRekeyReceipt{}, fmt.Errorf("recipients[%d] route-only access must not include topics", recipientIndex)
		}
		if recipient.Access == RekeyReadTopics && (len(recipient.Topics) == 0 || len(recipient.Topics) > 128) {
			return ScopeRekeyReceipt{}, fmt.Errorf("recipients[%d] read-topics access requires 1 to 128 topics", recipientIndex)
		}
		if recipient.Access != RekeyRouteOnly && recipient.Access != RekeyReadTopics {
			return ScopeRekeyReceipt{}, fmt.Errorf("recipients[%d] has an unknown access mode", recipientIndex)
		}

		native := &nativeRecipients[recipientIndex]
		native.abi_version = C.ASTER_ABI_VERSION
		native.struct_size = C.uint32_t(C.sizeof_aster_rekey_recipient_t)
		native.access = C.aster_rekey_access_t(recipient.Access)
		for index := range 32 {
			native.node_id[index] = C.uint8_t(recipient.NodeID[index])
		}
		if len(recipient.Topics) == 0 {
			continue
		}
		topicMemory := C.calloc(C.size_t(len(recipient.Topics)), C.size_t(C.sizeof_aster_bytes_t))
		if topicMemory == nil {
			return ScopeRekeyReceipt{}, fmt.Errorf("allocate native topics for recipients[%d]", recipientIndex)
		}
		nestedAllocations = append(nestedAllocations, topicMemory)
		nativeTopics := unsafe.Slice((*C.aster_bytes_t)(topicMemory), len(recipient.Topics))
		for topicIndex, topic := range recipient.Topics {
			if len(topic) == 0 || len([]byte(topic)) > 128 {
				return ScopeRekeyReceipt{}, fmt.Errorf("recipients[%d].topics[%d] must be between 1 and 128 UTF-8 bytes", recipientIndex, topicIndex)
			}
			value, allocation := nativeString(topic)
			nativeTopics[topicIndex] = value
			nestedAllocations = append(nestedAllocations, allocation)
		}
		native.topics = (*C.aster_bytes_t)(topicMemory)
		native.topic_count = C.size_t(len(recipient.Topics))
	}

	registry, registryAllocation := nativeBytes(signedPublicRegistry)
	scopeValue, scopeAllocation := nativeString(scope)
	defer freePointers(registryAllocation, scopeAllocation)
	request := C.aster_rekey_request_t{
		abi_version:                 C.ASTER_ABI_VERSION,
		struct_size:                 C.uint32_t(C.sizeof_aster_rekey_request_t),
		signed_public_registry:      registry,
		scope:                       scopeValue,
		minimum_registry_generation: C.uint64_t(minimumRegistryGeneration),
		new_epoch:                   C.uint64_t(newEpoch),
		recipients:                  (*C.aster_rekey_recipient_t)(recipientMemory),
		recipient_count:             C.size_t(len(recipients)),
	}
	output := C.aster_rekey_receipt_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_rekey_receipt_t),
	}
	if err := check(C.aster_node_rekey_scope(n.handle, &request, &output)); err != nil {
		return ScopeRekeyReceipt{}, err
	}
	return ScopeRekeyReceipt{
		Epoch:              uint64(output.epoch),
		RegistryGeneration: uint64(output.registry_generation),
		RecipientCount:     uint64(output.recipient_count),
		ControlSequence:    uint64(output.control_sequence),
	}, nil
}

func (n *Node) NewBlobWriter(topic, scope string, options BlobOptions) (*BlobWriter, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	var native C.aster_blob_publish_options_t
	if err := check(C.aster_blob_publish_options_init(&native)); err != nil {
		return nil, err
	}
	topicValue, a := nativeString(topic)
	scopeValue, b := nativeString(scope)
	mediaValue, c := nativeString(options.MediaType)
	schemaValue, d := nativeBytes(options.SchemaID)
	defer freePointers(a, b, c, d)
	native.topic = topicValue
	native.scope = scopeValue
	native.media_type = mediaValue
	native.schema_id = schemaValue
	native.priority = C.aster_priority_t(options.Priority)
	if options.ChunkSize != 0 {
		native.chunk_size = C.uint32_t(options.ChunkSize)
	}
	if options.TTLMillis != nil {
		native.has_ttl = 1
		native.ttl_ms = C.uint64_t(*options.TTLMillis)
	}
	writer := &BlobWriter{node: n}
	if err := check(C.aster_node_blob_writer_open(n.handle, &native, &writer.handle)); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(writer, func(value *BlobWriter) { _ = value.Close() })
	return writer, nil
}

// PublishBlobBatch finalizes and atomically publishes 2-64 distinct writers.
// On success each writer remains open and Finish returns its matching receipt;
// on failure every writer remains retryable.
func (n *Node) PublishBlobBatch(writers []*BlobWriter, policy BatchPublicationPolicy) (BatchPublishResult, error) {
	if len(writers) < 2 || len(writers) > 64 {
		return BatchPublishResult{}, fmt.Errorf("Blob batch must contain between 2 and 64 writers")
	}
	if policy != RetainedDual && policy != BatchOnly {
		return BatchPublishResult{}, fmt.Errorf("unknown batch publication policy %d", policy)
	}
	ordered := append([]*BlobWriter(nil), writers...)
	seenWriters := make(map[*BlobWriter]struct{}, len(ordered))
	for index, writer := range ordered {
		if writer == nil {
			return BatchPublishResult{}, fmt.Errorf("Blob batch writers[%d] is nil", index)
		}
		if _, exists := seenWriters[writer]; exists {
			return BatchPublishResult{}, fmt.Errorf("Blob batch contains a duplicate writer")
		}
		seenWriters[writer] = struct{}{}
	}
	sort.Slice(ordered, func(first, second int) bool {
		return reflect.ValueOf(ordered[first]).Pointer() < reflect.ValueOf(ordered[second]).Pointer()
	})
	for _, writer := range ordered {
		writer.mu.Lock()
	}
	defer func() {
		for index := len(ordered) - 1; index >= 0; index-- {
			ordered[index].mu.Unlock()
		}
	}()

	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return BatchPublishResult{}, err
	}
	nativeMemory := C.calloc(C.size_t(len(writers)), C.size_t(C.sizeof_aster_blob_writer_t))
	if nativeMemory == nil {
		return BatchPublishResult{}, fmt.Errorf("allocate native Blob batch writers")
	}
	defer C.free(nativeMemory)
	nativeHandles := unsafe.Slice((*C.aster_blob_writer_t)(nativeMemory), len(writers))
	seenHandles := make(map[uint64]struct{}, len(writers))
	for index, writer := range writers {
		if writer.node != n {
			return BatchPublishResult{}, fmt.Errorf("Blob batch writers[%d] belongs to another node", index)
		}
		if writer.handle.value == 0 {
			return BatchPublishResult{}, &Error{Status: C.ASTER_CLOSED, Detail: fmt.Sprintf("Blob batch writers[%d] is closed", index)}
		}
		handle := uint64(writer.handle.value)
		if _, exists := seenHandles[handle]; exists {
			return BatchPublishResult{}, fmt.Errorf("Blob batch contains a duplicate native writer handle")
		}
		seenHandles[handle] = struct{}{}
		nativeHandles[index] = writer.handle
	}
	request := C.aster_blob_publish_batch_request_t{
		abi_version:  C.ASTER_ABI_VERSION,
		struct_size:  C.uint32_t(C.sizeof_aster_blob_publish_batch_request_t),
		writers:      (*C.aster_blob_writer_t)(nativeMemory),
		writer_count: C.size_t(len(nativeHandles)),
		policy:       C.aster_batch_policy_t(policy),
	}
	var nativeResult C.aster_batch_result_t
	if err := check(C.aster_node_publish_blob_batch(n.handle, &request, &nativeResult)); err != nil {
		return BatchPublishResult{}, err
	}
	return readBatchResult(nativeResult)
}

func (w *BlobWriter) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handle.value == 0 {
		return 0, &Error{Status: C.ASTER_CLOSED, Detail: "Blob writer is closed"}
	}
	w.node.mu.Lock()
	defer w.node.mu.Unlock()
	if err := w.node.active(); err != nil {
		return 0, err
	}
	native, pointer := nativeBytes(value)
	defer freePointers(pointer)
	if err := check(C.aster_blob_writer_write(w.handle, native)); err != nil {
		return 0, err
	}
	return len(value), nil
}

func (w *BlobWriter) Finish() (BlobFinish, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handle.value == 0 {
		return BlobFinish{}, &Error{Status: C.ASTER_CLOSED, Detail: "Blob writer is closed"}
	}
	w.node.mu.Lock()
	defer w.node.mu.Unlock()
	if err := w.node.active(); err != nil {
		return BlobFinish{}, err
	}
	output := C.aster_blob_finish_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_blob_finish_t),
	}
	if err := check(C.aster_blob_writer_finish(w.handle, &output)); err != nil {
		return BlobFinish{}, err
	}
	result := BlobFinish{Receipt: receipt(output.receipt)}
	for index := range 32 {
		result.BlobID[index] = byte(output.blob_id[index])
	}
	return result, nil
}

func (w *BlobWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handle.value == 0 {
		return nil
	}
	runtime.SetFinalizer(w, nil)
	return check(C.aster_blob_writer_close(&w.handle))
}

func (n *Node) OpenBlobReader(topic, scope string, id BlobID) (*BlobReader, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	topicValue, a := nativeString(topic)
	scopeValue, b := nativeString(scope)
	defer freePointers(a, b)
	request := C.aster_blob_read_request_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_blob_read_request_t),
		topic:       topicValue,
		scope:       scopeValue,
	}
	for index := range 32 {
		request.blob_id[index] = C.uint8_t(id[index])
	}
	reader := &BlobReader{node: n}
	if err := check(C.aster_node_blob_reader_open(n.handle, &request, &reader.handle)); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(reader, func(value *BlobReader) { _ = value.Close() })
	return reader, nil
}

func (r *BlobReader) Read(output []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle.value == 0 {
		return 0, &Error{Status: C.ASTER_CLOSED, Detail: "Blob reader is closed"}
	}
	if len(output) == 0 {
		return 0, nil
	}
	r.node.mu.Lock()
	defer r.node.mu.Unlock()
	if err := r.node.active(); err != nil {
		return 0, err
	}
	var count C.size_t
	if err := check(C.aster_blob_reader_read(
		r.handle,
		(*C.uint8_t)(unsafe.Pointer(&output[0])),
		C.size_t(len(output)),
		&count,
	)); err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, io.EOF
	}
	return int(count), nil
}

func (r *BlobReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.handle.value == 0 {
		return nil
	}
	runtime.SetFinalizer(r, nil)
	return check(C.aster_blob_reader_close(&r.handle))
}

func queryRequest(query Query) (C.aster_query_request_t, []unsafe.Pointer) {
	topic, topicPointer := nativeString(query.Topic)
	scope, scopePointer := nativeString(query.Scope)
	key, keyPointer := nativeBytes(query.LogicalKey)
	value := C.aster_query_request_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_query_request_t),
		topic:       topic, scope: scope, logical_key: key,
		data_class: C.ASTER_DATA_CLASS_ANY,
		limit:      C.uint64_t(query.Limit),
	}
	if query.Class != nil {
		value.data_class = C.aster_data_class_t(*query.Class)
	}
	if query.IncludeDescendants {
		value.include_descendant_scopes = 1
	}
	if query.IncludeRecoverable {
		value.include_recoverable_versions = 1
	}
	if query.IncludeTombstones {
		value.include_tombstones = 1
	}
	return value, []unsafe.Pointer{topicPointer, scopePointer, keyPointer}
}

func (n *Node) Query(query Query) ([]Item, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	request, pointers := queryRequest(query)
	defer freePointers(pointers...)
	var result C.aster_query_t
	if err := check(C.aster_node_query(n.handle, &request, &result)); err != nil {
		return nil, err
	}
	defer C.aster_query_close(&result)
	var count C.size_t
	if err := check(C.aster_query_len(result, &count)); err != nil {
		return nil, err
	}
	items := make([]Item, 0, int(count))
	for index := C.size_t(0); index < count; index++ {
		item, err := queryItem(result, index)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func queryItem(result C.aster_query_t, index C.size_t) (Item, error) {
	raw := C.aster_item_t{abi_version: C.ASTER_ABI_VERSION, struct_size: C.uint32_t(C.sizeof_aster_item_t)}
	if err := check(C.aster_query_get(result, index, &raw)); err != nil {
		return Item{}, err
	}
	defer C.aster_item_free(&raw)
	return rawItem(raw), nil
}

func rawItem(raw C.aster_item_t) Item {
	item := Item{
		Class: DataClass(raw.data_class), Priority: Priority(raw.priority),
		CausalCounter: uint64(raw.causal_counter), Topic: string(ownedBytes(raw.topic)),
		Scope: string(ownedBytes(raw.scope)), OriginScope: string(ownedBytes(raw.origin_scope)),
		CurrentScope: string(ownedBytes(raw.current_scope)), LogicalKey: ownedBytes(raw.logical_key),
		Payload: ownedBytes(raw.payload), Tombstone: raw.tombstone != 0,
	}
	for i := range 32 {
		item.ItemID[i] = byte(raw.item_id[i])
		item.Publisher[i] = byte(raw.publisher[i])
	}
	if raw.has_event_sequence != 0 {
		value := uint64(raw.event_sequence)
		item.EventSequence = &value
	}
	return item
}

func (n *Node) Subscribe(topic, scope string, class *DataClass, includeDescendants bool) (*Subscription, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	topicValue, topicPointer := nativeString(topic)
	scopeValue, scopePointer := nativeString(scope)
	defer freePointers(topicPointer, scopePointer)
	request := C.aster_subscribe_request_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_subscribe_request_t),
		topic:       topicValue, scope: scopeValue, data_class: C.ASTER_DATA_CLASS_ANY,
	}
	if class != nil {
		request.data_class = C.aster_data_class_t(*class)
	}
	if includeDescendants {
		request.include_descendant_scopes = 1
	}
	var identifier C.uint64_t
	if err := check(C.aster_node_subscribe(n.handle, &request, &identifier)); err != nil {
		return nil, err
	}
	return &Subscription{node: n, ID: uint64(identifier)}, nil
}

func (s *Subscription) Poll(limit uint64) ([]Delivery, error) {
	n := s.node
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	request := C.aster_poll_request_t{
		abi_version:  C.ASTER_ABI_VERSION,
		struct_size:  C.uint32_t(C.sizeof_aster_poll_request_t),
		subscription: C.uint64_t(s.ID), limit: C.uint64_t(limit),
	}
	var result C.aster_deliveries_t
	if err := check(C.aster_node_poll(n.handle, &request, &result)); err != nil {
		return nil, err
	}
	defer C.aster_deliveries_close(&result)
	var count C.size_t
	if err := check(C.aster_deliveries_len(result, &count)); err != nil {
		return nil, err
	}
	values := make([]Delivery, 0, int(count))
	for index := C.size_t(0); index < count; index++ {
		raw := C.aster_delivery_t{abi_version: C.ASTER_ABI_VERSION, struct_size: C.uint32_t(C.sizeof_aster_delivery_t)}
		if err := check(C.aster_deliveries_get(result, index, &raw)); err != nil {
			return nil, err
		}
		values = append(values, Delivery{Subscription: uint64(raw.subscription), Attempt: uint64(raw.attempt), Item: rawItem(raw.item)})
		C.aster_delivery_free(&raw)
	}
	return values, nil
}

func (s *Subscription) Acknowledge(itemID [32]byte) error {
	n := s.node
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return err
	}
	request := C.aster_ack_request_t{
		abi_version:  C.ASTER_ABI_VERSION,
		struct_size:  C.uint32_t(C.sizeof_aster_ack_request_t),
		subscription: C.uint64_t(s.ID),
	}
	for index := range 32 {
		request.item_id[index] = C.uint8_t(itemID[index])
	}
	return check(C.aster_node_acknowledge(n.handle, &request))
}

func (n *Node) Conflicts(query Query) ([]Conflict, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	request, pointers := queryRequest(query)
	defer freePointers(pointers...)
	var result C.aster_conflicts_t
	if err := check(C.aster_node_conflicts(n.handle, &request, &result)); err != nil {
		return nil, err
	}
	defer C.aster_conflicts_close(&result)
	var count C.size_t
	if err := check(C.aster_conflicts_len(result, &count)); err != nil {
		return nil, err
	}
	values := make([]Conflict, 0, int(count))
	for index := C.size_t(0); index < count; index++ {
		raw := C.aster_conflict_t{abi_version: C.ASTER_ABI_VERSION, struct_size: C.uint32_t(C.sizeof_aster_conflict_t)}
		if err := check(C.aster_conflicts_get(result, index, &raw)); err != nil {
			return nil, err
		}
		ids := ownedBytes(raw.sibling_ids)
		value := Conflict{LogicalKey: ownedBytes(raw.logical_key)}
		for offset := 0; offset < len(ids); offset += 32 {
			var id [32]byte
			copy(id[:], ids[offset:offset+32])
			value.SiblingIDs = append(value.SiblingIDs, id)
		}
		if raw.has_merge_policy != 0 {
			policy := string(ownedBytes(raw.merge_policy))
			value.MergePolicy = &policy
		}
		C.aster_conflict_free(&raw)
		values = append(values, value)
	}
	return values, nil
}

func (n *Node) Resolve(topic, scope string, conflict Conflict, payload []byte, options PublishOptions) (PublishReceipt, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return PublishReceipt{}, err
	}
	ids := make([]byte, 0, len(conflict.SiblingIDs)*32)
	for _, id := range conflict.SiblingIDs {
		ids = append(ids, id[:]...)
	}
	topicValue, a := nativeString(topic)
	scopeValue, b := nativeString(scope)
	keyValue, c := nativeBytes(conflict.LogicalKey)
	idsValue, d := nativeBytes(ids)
	payloadValue, e := nativeBytes(payload)
	defer freePointers(a, b, c, d, e)
	request := C.aster_resolve_request_t{
		abi_version: C.ASTER_ABI_VERSION, struct_size: C.uint32_t(C.sizeof_aster_resolve_request_t),
		topic: topicValue, scope: scopeValue, logical_key: keyValue,
		expected_sibling_ids: idsValue, payload: payloadValue, priority: C.aster_priority_t(options.Priority),
	}
	if options.TTLMillis != nil {
		request.has_ttl = 1
		request.ttl_ms = C.uint64_t(*options.TTLMillis)
	}
	output := C.aster_publish_receipt_t{abi_version: C.ASTER_ABI_VERSION, struct_size: C.uint32_t(C.sizeof_aster_publish_receipt_t)}
	if err := check(C.aster_node_resolve(n.handle, &request, &output)); err != nil {
		return PublishReceipt{}, err
	}
	return receipt(output), nil
}

func (n *Node) SetEmissionThreshold(value EmissionThreshold) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return err
	}
	return check(C.aster_node_set_emission(n.handle, C.aster_priority_t(value)))
}

func (n *Node) EmissionThreshold() (EmissionThreshold, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return 0, err
	}
	var value C.aster_priority_t
	if err := check(C.aster_node_get_emission(n.handle, &value)); err != nil {
		return 0, err
	}
	return EmissionThreshold(value), nil
}

func rawPeer(raw C.aster_peer_snapshot_t) PeerSnapshot {
	value := PeerSnapshot{PeerState: PeerState(raw.peer_state), SyncState: SyncState(raw.sync_state)}
	for index := range 32 {
		value.Peer[index] = byte(raw.peer[index])
	}
	if raw.has_last_change != 0 {
		changed := uint64(raw.last_change_ms)
		value.LastChangeMillis = &changed
	}
	if raw.has_detail != 0 {
		detail := string(ownedBytes(raw.detail))
		value.Detail = &detail
	}
	return value
}

func (n *Node) PeerStatus(peer [32]byte) (PeerSnapshot, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return PeerSnapshot{}, err
	}
	request := C.aster_peer_request_t{abi_version: C.ASTER_ABI_VERSION, struct_size: C.uint32_t(C.sizeof_aster_peer_request_t)}
	for index := range 32 {
		request.peer[index] = C.uint8_t(peer[index])
	}
	raw := C.aster_peer_snapshot_t{abi_version: C.ASTER_ABI_VERSION, struct_size: C.uint32_t(C.sizeof_aster_peer_snapshot_t)}
	if err := check(C.aster_node_peer_status(n.handle, &request, &raw)); err != nil {
		return PeerSnapshot{}, err
	}
	defer C.aster_peer_snapshot_free(&raw)
	return rawPeer(raw), nil
}

func (n *Node) Peers() ([]PeerSnapshot, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	var result C.aster_peers_t
	if err := check(C.aster_node_peers(n.handle, &result)); err != nil {
		return nil, err
	}
	defer C.aster_peers_close(&result)
	var count C.size_t
	if err := check(C.aster_peers_len(result, &count)); err != nil {
		return nil, err
	}
	values := make([]PeerSnapshot, 0, int(count))
	for index := C.size_t(0); index < count; index++ {
		raw := C.aster_peer_snapshot_t{abi_version: C.ASTER_ABI_VERSION, struct_size: C.uint32_t(C.sizeof_aster_peer_snapshot_t)}
		if err := check(C.aster_peers_get(result, index, &raw)); err != nil {
			return nil, err
		}
		values = append(values, rawPeer(raw))
		C.aster_peer_snapshot_free(&raw)
	}
	return values, nil
}

func validateBridgePriorityMask(value PriorityMask) error {
	if value == 0 || value&^AllowAll != 0 {
		return fmt.Errorf("bridge priority mask must explicitly select bits 0 through 3")
	}
	return nil
}

func nativeBridgeTopics(topics []string, required bool) (*C.aster_bytes_t, C.size_t, func(), error) {
	if required && len(topics) == 0 {
		return nil, 0, func() {}, fmt.Errorf("bridge policy requires at least one topic")
	}
	if len(topics) > 128 {
		return nil, 0, func() {}, fmt.Errorf("bridge policy topics exceed 128 entries")
	}
	if len(topics) == 0 {
		return nil, 0, func() {}, nil
	}
	memory := C.calloc(C.size_t(len(topics)), C.size_t(C.sizeof_aster_bytes_t))
	if memory == nil {
		return nil, 0, func() {}, fmt.Errorf("allocate native bridge topics")
	}
	allocations := []unsafe.Pointer{memory}
	cleanup := func() { freePointers(allocations...) }
	native := unsafe.Slice((*C.aster_bytes_t)(memory), len(topics))
	for index, topic := range topics {
		if length := len([]byte(topic)); length == 0 || length > 128 {
			cleanup()
			return nil, 0, func() {}, fmt.Errorf("bridge topics[%d] must be between 1 and 128 UTF-8 bytes", index)
		}
		value, allocation := nativeString(topic)
		native[index] = value
		allocations = append(allocations, allocation)
	}
	return (*C.aster_bytes_t)(memory), C.size_t(len(topics)), cleanup, nil
}

// CreateBridgeEnrollment creates an opaque enrollment for one exact directed
// edge. It contains no application-readable credential or key bytes.
func (n *Node) CreateBridgeEnrollment(sourceScope string, sourceRouteEpoch uint64,
	targetScope string, targetRouteEpoch uint64) (*BridgeEnrollment, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	source, a := nativeString(sourceScope)
	target, b := nativeString(targetScope)
	defer freePointers(a, b)
	request := C.aster_bridge_enrollment_request_t{
		abi_version:  C.ASTER_ABI_VERSION,
		struct_size:  C.uint32_t(C.sizeof_aster_bridge_enrollment_request_t),
		source_scope: source, target_scope: target,
		source_route_epoch: C.uint64_t(sourceRouteEpoch),
		target_route_epoch: C.uint64_t(targetRouteEpoch),
	}
	value := &BridgeEnrollment{}
	if err := check(C.aster_node_bridge_enrollment_create(n.handle, &request, &value.handle)); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(value, func(enrollment *BridgeEnrollment) { _ = enrollment.Close() })
	return value, nil
}

func (e *BridgeEnrollment) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle.value == 0 {
		return nil
	}
	runtime.SetFinalizer(e, nil)
	return check(C.aster_bridge_enrollment_close(&e.handle))
}

func bridgeAuthorizationResult(raw C.aster_bridge_authorization_result_t) BridgeAuthorizationResult {
	value := BridgeAuthorizationResult{
		Generation: uint64(raw.generation), ControlSequence: uint64(raw.control_sequence),
		Enabled: raw.enabled != 0,
	}
	for index := range 32 {
		value.ID[index] = byte(raw.id[index])
	}
	return value
}

// EnableBridge is an authority operation. A well-formed native call consumes
// enrollment even when authority verification rejects it.
func (n *Node) EnableBridge(enrollment *BridgeEnrollment,
	policy BridgeAuthorizationPolicy) (BridgeAuthorizationResult, error) {
	if enrollment == nil {
		return BridgeAuthorizationResult{}, fmt.Errorf("bridge enrollment must not be nil")
	}
	if err := validateBridgePriorityMask(policy.AllowedPriorities); err != nil {
		return BridgeAuthorizationResult{}, err
	}
	if policy.MaxTotalHops == 0 || policy.MaxTotalHops > 8 {
		return BridgeAuthorizationResult{}, fmt.Errorf("bridge maximum total hops must be between 1 and 8")
	}
	topics, topicCount, cleanup, err := nativeBridgeTopics(policy.Topics, true)
	if err != nil {
		return BridgeAuthorizationResult{}, err
	}
	defer cleanup()
	enrollment.mu.Lock()
	defer enrollment.mu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if err = n.active(); err != nil {
		return BridgeAuthorizationResult{}, err
	}
	if enrollment.handle.value == 0 {
		return BridgeAuthorizationResult{}, &Error{Status: C.ASTER_CLOSED, Detail: "bridge enrollment is closed or consumed"}
	}
	native := C.aster_bridge_enable_policy_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_enable_policy_t),
		topics:      topics, topic_count: topicCount,
		allowed_priority_mask: C.aster_priority_mask_t(policy.AllowedPriorities),
		max_total_hops:        C.uint8_t(policy.MaxTotalHops),
	}
	output := C.aster_bridge_authorization_result_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_authorization_result_t),
	}
	status := C.aster_node_bridge_enable(n.handle, &enrollment.handle, &native, &output)
	if enrollment.handle.value == 0 {
		runtime.SetFinalizer(enrollment, nil)
	}
	if err = check(status); err != nil {
		return BridgeAuthorizationResult{}, err
	}
	return bridgeAuthorizationResult(output), nil
}

func (n *Node) DisableBridge(bridgeNode [32]byte, sourceScope,
	targetScope string) (BridgeAuthorizationResult, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return BridgeAuthorizationResult{}, err
	}
	source, a := nativeString(sourceScope)
	target, b := nativeString(targetScope)
	defer freePointers(a, b)
	request := C.aster_bridge_disable_request_t{
		abi_version:  C.ASTER_ABI_VERSION,
		struct_size:  C.uint32_t(C.sizeof_aster_bridge_disable_request_t),
		source_scope: source, target_scope: target,
	}
	for index := range 32 {
		request.bridge_node[index] = C.uint8_t(bridgeNode[index])
	}
	output := C.aster_bridge_authorization_result_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_authorization_result_t),
	}
	if err := check(C.aster_node_bridge_disable(n.handle, &request, &output)); err != nil {
		return BridgeAuthorizationResult{}, err
	}
	return bridgeAuthorizationResult(output), nil
}

func bridgeRouteResult(raw *C.aster_bridge_route_result_t) BridgeRouteResult {
	value := BridgeRouteResult{
		CurrentScope:      string(ownedBytes(raw.current_scope)),
		CurrentRouteEpoch: uint64(raw.current_route_epoch),
		HopCount:          uint8(raw.hop_count), Status: BridgeCommitStatus(raw.commit_status),
	}
	for index := range 32 {
		value.Handle[index] = byte(raw.handle[index])
		value.SourceItem[index] = byte(raw.source_item[index])
	}
	return value
}

func (n *Node) BridgeItem(sourceItem [32]byte, authorization BridgeAuthorizationID,
	policy BridgeNarrowingPolicy) (BridgeRouteResult, error) {
	if err := validateBridgePriorityMask(policy.AllowedPriorities); err != nil {
		return BridgeRouteResult{}, err
	}
	topics, topicCount, cleanup, err := nativeBridgeTopics(policy.Topics, false)
	if err != nil {
		return BridgeRouteResult{}, err
	}
	defer cleanup()
	n.mu.Lock()
	defer n.mu.Unlock()
	if err = n.active(); err != nil {
		return BridgeRouteResult{}, err
	}
	request := C.aster_bridge_item_request_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_item_request_t),
		topics:      topics, topic_count: topicCount,
		allowed_priority_mask: C.aster_priority_mask_t(policy.AllowedPriorities),
	}
	for index := range 32 {
		request.source_item[index] = C.uint8_t(sourceItem[index])
		request.authorization_id[index] = C.uint8_t(authorization[index])
	}
	output := C.aster_bridge_route_result_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_route_result_t),
	}
	if err = check(C.aster_node_bridge_item(n.handle, &request, &output)); err != nil {
		return BridgeRouteResult{}, err
	}
	defer C.aster_bridge_route_result_free(&output)
	return bridgeRouteResult(&output), nil
}

func (n *Node) ExtendBridgeRoute(route BridgeRouteHandle, authorization BridgeAuthorizationID,
	policy BridgeNarrowingPolicy) (BridgeRouteResult, error) {
	if err := validateBridgePriorityMask(policy.AllowedPriorities); err != nil {
		return BridgeRouteResult{}, err
	}
	topics, topicCount, cleanup, err := nativeBridgeTopics(policy.Topics, false)
	if err != nil {
		return BridgeRouteResult{}, err
	}
	defer cleanup()
	n.mu.Lock()
	defer n.mu.Unlock()
	if err = n.active(); err != nil {
		return BridgeRouteResult{}, err
	}
	request := C.aster_bridge_extend_request_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_extend_request_t),
		topics:      topics, topic_count: topicCount,
		allowed_priority_mask: C.aster_priority_mask_t(policy.AllowedPriorities),
	}
	for index := range 32 {
		request.route_handle[index] = C.uint8_t(route[index])
		request.authorization_id[index] = C.uint8_t(authorization[index])
	}
	output := C.aster_bridge_route_result_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_route_result_t),
	}
	if err = check(C.aster_node_bridge_extend(n.handle, &request, &output)); err != nil {
		return BridgeRouteResult{}, err
	}
	defer C.aster_bridge_route_result_free(&output)
	return bridgeRouteResult(&output), nil
}

func bridgeStatusRequest(id [32]byte) C.aster_bridge_status_request_t {
	request := C.aster_bridge_status_request_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_status_request_t),
	}
	for index := range 32 {
		request.id[index] = C.uint8_t(id[index])
	}
	return request
}

func decodeBridgeTopics(raw C.aster_owned_buffer_t, count uint64) ([]string, error) {
	if count > 128 {
		return nil, fmt.Errorf("native bridge topic count exceeds 128")
	}
	encoded := ownedBytes(raw)
	values := make([]string, 0, int(count))
	for range count {
		if len(encoded) < 2 {
			return nil, fmt.Errorf("native bridge topic list is truncated")
		}
		length := int(binary.BigEndian.Uint16(encoded[:2]))
		encoded = encoded[2:]
		if length == 0 || length > len(encoded) {
			return nil, fmt.Errorf("native bridge topic length is invalid")
		}
		values = append(values, string(encoded[:length]))
		encoded = encoded[length:]
	}
	if len(encoded) != 0 {
		return nil, fmt.Errorf("native bridge topic list has trailing bytes")
	}
	return values, nil
}

func rawBridgeAuthorizationStatus(raw *C.aster_bridge_authorization_status_t) (BridgeAuthorizationStatus, error) {
	topics, err := decodeBridgeTopics(raw.topics, uint64(raw.topic_count))
	if err != nil {
		return BridgeAuthorizationStatus{}, err
	}
	value := BridgeAuthorizationStatus{
		SourceScope: string(ownedBytes(raw.source_scope)), TargetScope: string(ownedBytes(raw.target_scope)),
		Generation: uint64(raw.generation), ControlSequence: uint64(raw.control_sequence),
		Applied: raw.applied != 0, Current: raw.current != 0, Enabled: raw.enabled != 0,
		Usable: raw.usable != 0, Topics: topics,
		AllowedPriorities: PriorityMask(raw.allowed_priority_mask),
	}
	for index := range 32 {
		value.ID[index] = byte(raw.id[index])
		value.Authority[index] = byte(raw.authority[index])
		value.BridgeNode[index] = byte(raw.bridge_node[index])
	}
	if raw.has_source_route_epoch != 0 {
		epoch := uint64(raw.source_route_epoch)
		value.SourceRouteEpoch = &epoch
	}
	if raw.has_target_route_epoch != 0 {
		epoch := uint64(raw.target_route_epoch)
		value.TargetRouteEpoch = &epoch
	}
	if raw.has_max_total_hops != 0 {
		hops := uint8(raw.max_total_hops)
		value.MaxTotalHops = &hops
	}
	return value, nil
}

func (n *Node) BridgeAuthorizationStatus(id BridgeAuthorizationID) (BridgeAuthorizationStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return BridgeAuthorizationStatus{}, err
	}
	request := bridgeStatusRequest([32]byte(id))
	raw := C.aster_bridge_authorization_status_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_authorization_status_t),
	}
	if err := check(C.aster_node_bridge_authorization_status(n.handle, &request, &raw)); err != nil {
		return BridgeAuthorizationStatus{}, err
	}
	defer C.aster_bridge_authorization_status_free(&raw)
	return rawBridgeAuthorizationStatus(&raw)
}

func bridgePageRequest(after *[32]byte, limit uint64) C.aster_bridge_page_request_t {
	request := C.aster_bridge_page_request_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_page_request_t),
		limit:       C.uint64_t(limit),
	}
	if after != nil {
		request.has_after = 1
		for index := range 32 {
			request.after[index] = C.uint8_t(after[index])
		}
	}
	return request
}

func (n *Node) BridgeAuthorizations(after *BridgeAuthorizationID, limit uint64) ([]BridgeAuthorizationStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	var cursor *[32]byte
	if after != nil {
		value := [32]byte(*after)
		cursor = &value
	}
	request := bridgePageRequest(cursor, limit)
	var page C.aster_bridge_authorizations_t
	if err := check(C.aster_node_bridge_authorizations(n.handle, &request, &page)); err != nil {
		return nil, err
	}
	defer C.aster_bridge_authorizations_close(&page)
	var count C.size_t
	if err := check(C.aster_bridge_authorizations_len(page, &count)); err != nil {
		return nil, err
	}
	values := make([]BridgeAuthorizationStatus, 0, int(count))
	for index := C.size_t(0); index < count; index++ {
		raw := C.aster_bridge_authorization_status_t{
			abi_version: C.ASTER_ABI_VERSION,
			struct_size: C.uint32_t(C.sizeof_aster_bridge_authorization_status_t),
		}
		if err := check(C.aster_bridge_authorizations_get(page, index, &raw)); err != nil {
			return nil, err
		}
		value, conversionError := rawBridgeAuthorizationStatus(&raw)
		C.aster_bridge_authorization_status_free(&raw)
		if conversionError != nil {
			return nil, conversionError
		}
		values = append(values, value)
	}
	return values, nil
}

func rawBridgeRouteStatus(raw *C.aster_bridge_route_status_t) BridgeRouteStatus {
	value := BridgeRouteStatus{
		OriginScope: string(ownedBytes(raw.origin_scope)), OriginRouteEpoch: uint64(raw.origin_route_epoch),
		CurrentScope: string(ownedBytes(raw.current_scope)), CurrentRouteEpoch: uint64(raw.current_route_epoch),
		Topic: string(ownedBytes(raw.topic)), Priority: Priority(raw.priority), HopCount: uint8(raw.hop_count),
		Active: raw.active != 0, Live: raw.live != 0,
	}
	for index := range 32 {
		value.Handle[index] = byte(raw.handle[index])
		value.SourceItem[index] = byte(raw.source_item[index])
	}
	return value
}

func (n *Node) BridgeRouteStatus(handle BridgeRouteHandle) (BridgeRouteStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return BridgeRouteStatus{}, err
	}
	request := bridgeStatusRequest([32]byte(handle))
	raw := C.aster_bridge_route_status_t{
		abi_version: C.ASTER_ABI_VERSION,
		struct_size: C.uint32_t(C.sizeof_aster_bridge_route_status_t),
	}
	if err := check(C.aster_node_bridge_route_status(n.handle, &request, &raw)); err != nil {
		return BridgeRouteStatus{}, err
	}
	defer C.aster_bridge_route_status_free(&raw)
	return rawBridgeRouteStatus(&raw), nil
}

func (n *Node) BridgeRoutes(after *BridgeRouteHandle, limit uint64) ([]BridgeRouteStatus, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return nil, err
	}
	var cursor *[32]byte
	if after != nil {
		value := [32]byte(*after)
		cursor = &value
	}
	request := bridgePageRequest(cursor, limit)
	var page C.aster_bridge_routes_t
	if err := check(C.aster_node_bridge_routes(n.handle, &request, &page)); err != nil {
		return nil, err
	}
	defer C.aster_bridge_routes_close(&page)
	var count C.size_t
	if err := check(C.aster_bridge_routes_len(page, &count)); err != nil {
		return nil, err
	}
	values := make([]BridgeRouteStatus, 0, int(count))
	for index := C.size_t(0); index < count; index++ {
		raw := C.aster_bridge_route_status_t{
			abi_version: C.ASTER_ABI_VERSION,
			struct_size: C.uint32_t(C.sizeof_aster_bridge_route_status_t),
		}
		if err := check(C.aster_bridge_routes_get(page, index, &raw)); err != nil {
			return nil, err
		}
		values = append(values, rawBridgeRouteStatus(&raw))
		C.aster_bridge_route_status_free(&raw)
	}
	return values, nil
}

func (n *Node) SetBridgeFilters(filters []BridgeFilter) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.active(); err != nil {
		return err
	}
	if len(filters) == 0 {
		return check(C.aster_node_set_bridge_filters(n.handle, nil, 0))
	}
	native := make([]C.aster_bridge_filter_t, len(filters))
	pointers := make([]unsafe.Pointer, 0, len(filters)*3)
	defer func() { freePointers(pointers...) }()
	for index, filter := range filters {
		from, a := nativeString(filter.FromScope)
		to, b := nativeString(filter.ToScope)
		topic, c := nativeString(filter.Topic)
		pointers = append(pointers, a, b, c)
		native[index] = C.aster_bridge_filter_t{
			abi_version: C.ASTER_ABI_VERSION, struct_size: C.uint32_t(C.sizeof_aster_bridge_filter_t),
			from_scope: from, to_scope: to, topic: topic, minimum_priority: C.aster_priority_t(filter.MinimumPriority),
		}
	}
	return check(C.aster_node_set_bridge_filters(n.handle, &native[0], C.size_t(len(native))))
}
