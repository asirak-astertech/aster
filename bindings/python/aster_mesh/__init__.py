"""First-class, dependency-free ctypes binding for the Aster C ABI."""

from __future__ import annotations

import ctypes as _c
import io as _io
import os as _os
import pathlib as _pathlib
import sys as _sys
import threading as _threading
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import Optional

ABI_VERSION = 1
_ANY_CLASS = 0xFFFFFFFF
_MAX_REKEY_REGISTRY_BYTES = 16 * 1024 * 1024
_MAX_REKEY_RECIPIENTS = 128
_MAX_REKEY_TOPICS = 128
_MAX_NAME_BYTES = 128


class DataClass(IntEnum):
    STATE = 0
    EVENT = 1
    RECORD = 2
    BLOB = 3


class Priority(IntEnum):
    ROUTINE = 0
    PRIORITY = 1
    IMMEDIATE = 2
    FLASH = 3


class BatchPublicationPolicy(IntEnum):
    """Retention policy for one explicit atomic publication."""

    RETAINED_DUAL = 0
    BATCH_ONLY = 1


class EmissionThreshold(IntEnum):
    ROUTINE = 0
    PRIORITY = 1
    IMMEDIATE = 2
    FLASH = 3
    RECEIVE_ONLY = 4


class RekeyAccess(IntEnum):
    """Explicit access assigned to a fresh scope epoch recipient."""

    ROUTE_ONLY = 1
    READ_TOPICS = 2


class PriorityMask(IntFlag):
    """Explicit bridge-policy subset of source-authenticated priorities."""

    ROUTINE = 1 << Priority.ROUTINE
    PRIORITY = 1 << Priority.PRIORITY
    IMMEDIATE = 1 << Priority.IMMEDIATE
    FLASH = 1 << Priority.FLASH
    ALL = ROUTINE | PRIORITY | IMMEDIATE | FLASH


class BridgeCommitStatus(IntEnum):
    ACTIVE = 0
    RETAINED_ALTERNATE = 1
    DUPLICATE_ACTIVE = 2
    DUPLICATE_INACTIVE = 3


class AsterError(RuntimeError):
    """Stable native status plus its sanitized diagnostic."""

    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(message or f"Aster native status {status}")


class _Handle(_c.Structure):
    _fields_ = [("value", _c.c_uint64)]


class _Bytes(_c.Structure):
    _fields_ = [("data", _c.POINTER(_c.c_uint8)), ("len", _c.c_size_t)]


class _Owned(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("data", _c.POINTER(_c.c_uint8)),
        ("len", _c.c_size_t),
    ]

    @classmethod
    def empty(cls) -> _Owned:
        value = cls()
        value.abi_version = ABI_VERSION
        value.struct_size = _c.sizeof(cls)
        return value


class _Options(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("store_path", _Bytes),
        ("provisioning_bundle", _Bytes),
        ("max_items", _c.c_uint64),
        ("max_bytes", _c.c_uint64),
        ("tombstone_retention_ms", _c.c_uint64),
        ("superseded_retention_ms", _c.c_uint64),
        ("priority_cap", _c.c_uint32),
        ("emission_threshold", _c.c_uint32),
    ]


class _Publish(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("data_class", _c.c_uint32),
        ("priority", _c.c_uint32),
        ("topic", _Bytes),
        ("scope", _Bytes),
        ("logical_key", _Bytes),
        ("payload", _Bytes),
        ("ttl_ms", _c.c_uint64),
        ("has_ttl", _c.c_uint8),
        ("tombstone", _c.c_uint8),
        ("reserved", _c.c_uint8 * 6),
    ]


class _PublishBatch(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("items", _c.POINTER(_Publish)),
        ("item_count", _c.c_size_t),
        ("policy", _c.c_uint32),
        ("reserved", _c.c_uint32),
    ]


class _Receipt(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("item_id", _c.c_uint8 * 32),
        ("publisher", _c.c_uint8 * 32),
        ("causal_counter", _c.c_uint64),
        ("event_sequence", _c.c_uint64),
        ("has_event_sequence", _c.c_uint8),
        ("effective_priority", _c.c_uint8),
        ("reserved", _c.c_uint8 * 6),
    ]


class _ItemId(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("bytes", _c.c_uint8 * 32),
    ]


class _BlobPublishOptions(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("topic", _Bytes),
        ("scope", _Bytes),
        ("media_type", _Bytes),
        ("schema_id", _Bytes),
        ("ttl_ms", _c.c_uint64),
        ("chunk_size", _c.c_uint32),
        ("priority", _c.c_uint32),
        ("has_ttl", _c.c_uint8),
        ("reserved", _c.c_uint8 * 7),
    ]


class _BlobFinish(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("blob_id", _c.c_uint8 * 32),
        ("receipt", _Receipt),
    ]


class _BlobPublishBatch(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("writers", _c.POINTER(_Handle)),
        ("writer_count", _c.c_size_t),
        ("policy", _c.c_uint32),
        ("reserved", _c.c_uint32),
    ]


class _BlobReadRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("topic", _Bytes),
        ("scope", _Bytes),
        ("blob_id", _c.c_uint8 * 32),
    ]


class _QueryRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("topic", _Bytes),
        ("scope", _Bytes),
        ("logical_key", _Bytes),
        ("data_class", _c.c_uint32),
        ("include_descendant_scopes", _c.c_uint8),
        ("include_recoverable_versions", _c.c_uint8),
        ("include_tombstones", _c.c_uint8),
        ("reserved", _c.c_uint8),
        ("limit", _c.c_uint64),
    ]


class _Item(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("item_id", _c.c_uint8 * 32),
        ("publisher", _c.c_uint8 * 32),
        ("data_class", _c.c_uint32),
        ("priority", _c.c_uint32),
        ("causal_counter", _c.c_uint64),
        ("event_sequence", _c.c_uint64),
        ("has_event_sequence", _c.c_uint8),
        ("tombstone", _c.c_uint8),
        ("reserved", _c.c_uint8 * 6),
        ("topic", _Owned),
        ("scope", _Owned),
        ("origin_scope", _Owned),
        ("current_scope", _Owned),
        ("logical_key", _Owned),
        ("payload", _Owned),
    ]


class _Subscribe(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("topic", _Bytes),
        ("scope", _Bytes),
        ("data_class", _c.c_uint32),
        ("include_descendant_scopes", _c.c_uint8),
        ("reserved", _c.c_uint8 * 3),
    ]


class _Poll(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("subscription", _c.c_uint64),
        ("limit", _c.c_uint64),
    ]


class _Delivery(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("subscription", _c.c_uint64),
        ("attempt", _c.c_uint64),
        ("item", _Item),
    ]


class _Ack(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("subscription", _c.c_uint64),
        ("item_id", _c.c_uint8 * 32),
    ]


class _Conflict(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("logical_key", _Owned),
        ("sibling_ids", _Owned),
        ("merge_policy", _Owned),
        ("has_merge_policy", _c.c_uint8),
        ("reserved", _c.c_uint8 * 7),
    ]


class _Resolve(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("topic", _Bytes),
        ("scope", _Bytes),
        ("logical_key", _Bytes),
        ("expected_sibling_ids", _Bytes),
        ("payload", _Bytes),
        ("priority", _c.c_uint32),
        ("reserved0", _c.c_uint32),
        ("ttl_ms", _c.c_uint64),
        ("has_ttl", _c.c_uint8),
        ("reserved", _c.c_uint8 * 7),
    ]


class _PeerSnapshot(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("peer", _c.c_uint8 * 32),
        ("peer_state", _c.c_uint32),
        ("sync_state", _c.c_uint32),
        ("last_change_ms", _c.c_uint64),
        ("has_last_change", _c.c_uint8),
        ("has_detail", _c.c_uint8),
        ("reserved", _c.c_uint8 * 6),
        ("detail", _Owned),
    ]


class _PeerRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("peer", _c.c_uint8 * 32),
    ]


class _BridgeFilter(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("from_scope", _Bytes),
        ("to_scope", _Bytes),
        ("topic", _Bytes),
        ("minimum_priority", _c.c_uint32),
        ("reserved", _c.c_uint32),
    ]


class _BridgeEnrollmentRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("source_scope", _Bytes),
        ("target_scope", _Bytes),
        ("source_route_epoch", _c.c_uint64),
        ("target_route_epoch", _c.c_uint64),
        ("reserved", _c.c_uint8 * 8),
    ]


class _BridgeEnablePolicy(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("topics", _c.POINTER(_Bytes)),
        ("topic_count", _c.c_size_t),
        ("allowed_priority_mask", _c.c_uint8),
        ("max_total_hops", _c.c_uint8),
        ("reserved", _c.c_uint8 * 6),
    ]


class _BridgeDisableRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("bridge_node", _c.c_uint8 * 32),
        ("source_scope", _Bytes),
        ("target_scope", _Bytes),
        ("reserved", _c.c_uint8 * 8),
    ]


class _BridgeItemRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("source_item", _c.c_uint8 * 32),
        ("authorization_id", _c.c_uint8 * 32),
        ("topics", _c.POINTER(_Bytes)),
        ("topic_count", _c.c_size_t),
        ("allowed_priority_mask", _c.c_uint8),
        ("reserved", _c.c_uint8 * 7),
    ]


class _BridgeExtendRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("route_handle", _c.c_uint8 * 32),
        ("authorization_id", _c.c_uint8 * 32),
        ("topics", _c.POINTER(_Bytes)),
        ("topic_count", _c.c_size_t),
        ("allowed_priority_mask", _c.c_uint8),
        ("reserved", _c.c_uint8 * 7),
    ]


class _BridgeAuthorizationResult(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("id", _c.c_uint8 * 32),
        ("generation", _c.c_uint64),
        ("control_sequence", _c.c_uint64),
        ("enabled", _c.c_uint8),
        ("reserved", _c.c_uint8 * 7),
    ]


class _BridgeRouteResult(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("handle", _c.c_uint8 * 32),
        ("source_item", _c.c_uint8 * 32),
        ("current_route_epoch", _c.c_uint64),
        ("commit_status", _c.c_uint32),
        ("hop_count", _c.c_uint8),
        ("reserved", _c.c_uint8 * 3),
        ("current_scope", _Owned),
    ]


class _BridgeStatusRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("id", _c.c_uint8 * 32),
        ("reserved", _c.c_uint8 * 8),
    ]


class _BridgePageRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("after", _c.c_uint8 * 32),
        ("limit", _c.c_uint64),
        ("has_after", _c.c_uint8),
        ("reserved", _c.c_uint8 * 7),
    ]


class _BridgeAuthorizationStatus(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("id", _c.c_uint8 * 32),
        ("authority", _c.c_uint8 * 32),
        ("bridge_node", _c.c_uint8 * 32),
        ("generation", _c.c_uint64),
        ("control_sequence", _c.c_uint64),
        ("source_route_epoch", _c.c_uint64),
        ("target_route_epoch", _c.c_uint64),
        ("topic_count", _c.c_uint64),
        ("allowed_priority_mask", _c.c_uint8),
        ("max_total_hops", _c.c_uint8),
        ("applied", _c.c_uint8),
        ("current", _c.c_uint8),
        ("enabled", _c.c_uint8),
        ("usable", _c.c_uint8),
        ("has_source_route_epoch", _c.c_uint8),
        ("has_target_route_epoch", _c.c_uint8),
        ("has_max_total_hops", _c.c_uint8),
        ("reserved", _c.c_uint8 * 7),
        ("source_scope", _Owned),
        ("target_scope", _Owned),
        ("topics", _Owned),
    ]


class _BridgeRouteStatus(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("handle", _c.c_uint8 * 32),
        ("source_item", _c.c_uint8 * 32),
        ("origin_route_epoch", _c.c_uint64),
        ("current_route_epoch", _c.c_uint64),
        ("priority", _c.c_uint32),
        ("hop_count", _c.c_uint8),
        ("active", _c.c_uint8),
        ("live", _c.c_uint8),
        ("reserved", _c.c_uint8),
        ("origin_scope", _Owned),
        ("current_scope", _Owned),
        ("topic", _Owned),
    ]


class _RekeyRecipient(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("node_id", _c.c_uint8 * 32),
        ("access", _c.c_uint32),
        ("reserved", _c.c_uint32),
        ("topics", _c.POINTER(_Bytes)),
        ("topic_count", _c.c_size_t),
    ]


class _RekeyRequest(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("signed_public_registry", _Bytes),
        ("scope", _Bytes),
        ("minimum_registry_generation", _c.c_uint64),
        ("new_epoch", _c.c_uint64),
        ("recipients", _c.POINTER(_RekeyRecipient)),
        ("recipient_count", _c.c_size_t),
    ]


class _RekeyReceipt(_c.Structure):
    _fields_ = [
        ("abi_version", _c.c_uint32),
        ("struct_size", _c.c_uint32),
        ("epoch", _c.c_uint64),
        ("registry_generation", _c.c_uint64),
        ("recipient_count", _c.c_uint64),
        ("control_sequence", _c.c_uint64),
    ]


def _versioned(value):
    value.abi_version = ABI_VERSION
    value.struct_size = _c.sizeof(type(value))
    return value


def _input(value: bytes | str | None):
    if value is None:
        return _Bytes(), None
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if not raw:
        return _Bytes(), None
    storage = (_c.c_uint8 * len(raw)).from_buffer_copy(raw)
    return _Bytes(_c.cast(storage, _c.POINTER(_c.c_uint8)), len(raw)), storage


def _bounded_name(value: str, label: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    length = len(value.encode("utf-8"))
    if not 1 <= length <= _MAX_NAME_BYTES:
        raise ValueError(f"{label} must be between 1 and 128 UTF-8 bytes")


def _bounded_u64(value: int, label: str, *, nonzero: bool = False) -> None:
    minimum = 1 if nonzero else 0
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= 0xFFFFFFFFFFFFFFFF:
        qualifier = "nonzero " if nonzero else ""
        raise ValueError(f"{label} must be a {qualifier}uint64")


def _copy(buffer: _Owned) -> bytes:
    return _c.string_at(buffer.data, buffer.len) if buffer.len else b""


def _find_library() -> str:
    explicit = _os.environ.get("ASTER_MESH_LIBRARY")
    if explicit:
        return explicit
    root = _pathlib.Path(__file__).resolve().parents[3]
    names = (
        ("aster_ffi.dll",) if _sys.platform == "win32" else
        ("libaster_ffi.dylib", "libaster_ffi.so")
    )
    for profile in ("debug", "release"):
        for name in names:
            candidate = root / "target" / profile / name
            if candidate.is_file():
                return str(candidate)
    raise RuntimeError("build aster-ffi or set ASTER_MESH_LIBRARY")


_lib = _c.CDLL(_find_library())
_lib.aster_node_options_init.argtypes = [_c.POINTER(_Options)]
_lib.aster_node_open.argtypes = [_c.POINTER(_Options), _c.POINTER(_Handle)]
_lib.aster_node_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_node_zeroize.argtypes = [_c.POINTER(_Handle)]
_lib.aster_node_publish.argtypes = [_Handle, _c.POINTER(_Publish), _c.POINTER(_Receipt)]
_lib.aster_node_publish_batch.argtypes = [
    _Handle, _c.POINTER(_PublishBatch), _c.POINTER(_Handle),
]
_lib.aster_batch_result_len.argtypes = [_Handle, _c.POINTER(_c.c_size_t)]
_lib.aster_batch_result_get.argtypes = [
    _Handle, _c.c_size_t, _c.POINTER(_Receipt),
]
_lib.aster_batch_result_evicted_len.argtypes = [
    _Handle, _c.POINTER(_c.c_size_t),
]
_lib.aster_batch_result_evicted_get.argtypes = [
    _Handle, _c.c_size_t, _c.POINTER(_ItemId),
]
_lib.aster_batch_result_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_node_rekey_scope.argtypes = [
    _Handle, _c.POINTER(_RekeyRequest), _c.POINTER(_RekeyReceipt),
]
_lib.aster_blob_publish_options_init.argtypes = [_c.POINTER(_BlobPublishOptions)]
_lib.aster_node_blob_writer_open.argtypes = [
    _Handle, _c.POINTER(_BlobPublishOptions), _c.POINTER(_Handle),
]
_lib.aster_blob_writer_write.argtypes = [_Handle, _Bytes]
_lib.aster_blob_writer_finish.argtypes = [_Handle, _c.POINTER(_BlobFinish)]
_lib.aster_node_publish_blob_batch.argtypes = [
    _Handle, _c.POINTER(_BlobPublishBatch), _c.POINTER(_Handle),
]
_lib.aster_blob_writer_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_node_blob_reader_open.argtypes = [
    _Handle, _c.POINTER(_BlobReadRequest), _c.POINTER(_Handle),
]
_lib.aster_blob_reader_read.argtypes = [
    _Handle, _c.POINTER(_c.c_uint8), _c.c_size_t, _c.POINTER(_c.c_size_t),
]
_lib.aster_blob_reader_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_node_query.argtypes = [_Handle, _c.POINTER(_QueryRequest), _c.POINTER(_Handle)]
_lib.aster_query_len.argtypes = [_Handle, _c.POINTER(_c.c_size_t)]
_lib.aster_query_get.argtypes = [_Handle, _c.c_size_t, _c.POINTER(_Item)]
_lib.aster_query_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_item_free.argtypes = [_c.POINTER(_Item)]
_lib.aster_node_subscribe.argtypes = [_Handle, _c.POINTER(_Subscribe), _c.POINTER(_c.c_uint64)]
_lib.aster_node_poll.argtypes = [_Handle, _c.POINTER(_Poll), _c.POINTER(_Handle)]
_lib.aster_deliveries_len.argtypes = [_Handle, _c.POINTER(_c.c_size_t)]
_lib.aster_deliveries_get.argtypes = [_Handle, _c.c_size_t, _c.POINTER(_Delivery)]
_lib.aster_deliveries_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_delivery_free.argtypes = [_c.POINTER(_Delivery)]
_lib.aster_node_acknowledge.argtypes = [_Handle, _c.POINTER(_Ack)]
_lib.aster_node_conflicts.argtypes = [_Handle, _c.POINTER(_QueryRequest), _c.POINTER(_Handle)]
_lib.aster_conflicts_len.argtypes = [_Handle, _c.POINTER(_c.c_size_t)]
_lib.aster_conflicts_get.argtypes = [_Handle, _c.c_size_t, _c.POINTER(_Conflict)]
_lib.aster_conflicts_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_conflict_free.argtypes = [_c.POINTER(_Conflict)]
_lib.aster_node_resolve.argtypes = [_Handle, _c.POINTER(_Resolve), _c.POINTER(_Receipt)]
_lib.aster_node_set_emission.argtypes = [_Handle, _c.c_uint32]
_lib.aster_node_get_emission.argtypes = [_Handle, _c.POINTER(_c.c_uint32)]
_lib.aster_node_peer_status.argtypes = [_Handle, _c.POINTER(_PeerRequest), _c.POINTER(_PeerSnapshot)]
_lib.aster_node_peers.argtypes = [_Handle, _c.POINTER(_Handle)]
_lib.aster_peers_len.argtypes = [_Handle, _c.POINTER(_c.c_size_t)]
_lib.aster_peers_get.argtypes = [_Handle, _c.c_size_t, _c.POINTER(_PeerSnapshot)]
_lib.aster_peers_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_peer_snapshot_free.argtypes = [_c.POINTER(_PeerSnapshot)]
_lib.aster_node_bridge_enrollment_create.argtypes = [
    _Handle, _c.POINTER(_BridgeEnrollmentRequest), _c.POINTER(_Handle),
]
_lib.aster_bridge_enrollment_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_node_bridge_enable.argtypes = [
    _Handle, _c.POINTER(_Handle), _c.POINTER(_BridgeEnablePolicy),
    _c.POINTER(_BridgeAuthorizationResult),
]
_lib.aster_node_bridge_disable.argtypes = [
    _Handle, _c.POINTER(_BridgeDisableRequest),
    _c.POINTER(_BridgeAuthorizationResult),
]
_lib.aster_node_bridge_item.argtypes = [
    _Handle, _c.POINTER(_BridgeItemRequest), _c.POINTER(_BridgeRouteResult),
]
_lib.aster_node_bridge_extend.argtypes = [
    _Handle, _c.POINTER(_BridgeExtendRequest), _c.POINTER(_BridgeRouteResult),
]
_lib.aster_bridge_route_result_free.argtypes = [_c.POINTER(_BridgeRouteResult)]
_lib.aster_node_bridge_authorization_status.argtypes = [
    _Handle, _c.POINTER(_BridgeStatusRequest),
    _c.POINTER(_BridgeAuthorizationStatus),
]
_lib.aster_node_bridge_authorizations.argtypes = [
    _Handle, _c.POINTER(_BridgePageRequest), _c.POINTER(_Handle),
]
_lib.aster_bridge_authorizations_len.argtypes = [_Handle, _c.POINTER(_c.c_size_t)]
_lib.aster_bridge_authorizations_get.argtypes = [
    _Handle, _c.c_size_t, _c.POINTER(_BridgeAuthorizationStatus),
]
_lib.aster_bridge_authorizations_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_bridge_authorization_status_free.argtypes = [
    _c.POINTER(_BridgeAuthorizationStatus),
]
_lib.aster_node_bridge_route_status.argtypes = [
    _Handle, _c.POINTER(_BridgeStatusRequest), _c.POINTER(_BridgeRouteStatus),
]
_lib.aster_node_bridge_routes.argtypes = [
    _Handle, _c.POINTER(_BridgePageRequest), _c.POINTER(_Handle),
]
_lib.aster_bridge_routes_len.argtypes = [_Handle, _c.POINTER(_c.c_size_t)]
_lib.aster_bridge_routes_get.argtypes = [
    _Handle, _c.c_size_t, _c.POINTER(_BridgeRouteStatus),
]
_lib.aster_bridge_routes_close.argtypes = [_c.POINTER(_Handle)]
_lib.aster_bridge_route_status_free.argtypes = [_c.POINTER(_BridgeRouteStatus)]
_lib.aster_node_set_bridge_filters.argtypes = [_Handle, _c.POINTER(_BridgeFilter), _c.c_size_t]
_lib.aster_last_error.argtypes = [_c.POINTER(_Owned)]
_lib.aster_buffer_free.argtypes = [_c.POINTER(_Owned)]
for _name in dir(_lib):
    if _name.startswith("aster_"):
        getattr(_lib, _name).restype = _c.c_uint32

for _name in (
    "aster_protocol_version",
    "aster_replication_wire_version",
    "aster_default_semantic_version",
    "aster_highest_supported_semantic_version",
):
    getattr(_lib, _name).argtypes = []
    getattr(_lib, _name).restype = _c.c_uint16

# PROTOCOL_VERSION is retained as the legacy name for the stable wire/profile
# version. It is deliberately not the authenticated session semantic version.
PROTOCOL_VERSION = int(_lib.aster_protocol_version())
REPLICATION_WIRE_VERSION = int(_lib.aster_replication_wire_version())
DEFAULT_SEMANTIC_VERSION = int(_lib.aster_default_semantic_version())
HIGHEST_SUPPORTED_SEMANTIC_VERSION = int(
    _lib.aster_highest_supported_semantic_version()
)


def _message() -> str:
    output = _Owned.empty()
    if _lib.aster_last_error(_c.byref(output)) != 0:
        return "native error (diagnostic unavailable)"
    try:
        return _copy(output).decode("utf-8", "replace")
    finally:
        _lib.aster_buffer_free(_c.byref(output))


def _check(status: int) -> None:
    if status:
        raise AsterError(status, _message())


@dataclass(frozen=True)
class PublishReceipt:
    item_id: bytes
    publisher: bytes
    causal_counter: int
    event_sequence: Optional[int]
    effective_priority: Priority


@dataclass(frozen=True)
class BatchPublishItem:
    """One member of a bounded, ordered atomic publication."""

    data_class: DataClass
    topic: str
    scope: str
    payload: bytes
    logical_key: bytes = b""
    priority: Priority = Priority.ROUTINE
    ttl_ms: Optional[int] = None
    tombstone: bool = False


@dataclass(frozen=True)
class BatchPublishResult:
    """Ordered receipts and aggregate victims from one atomic commit."""

    items: tuple[PublishReceipt, ...]
    evicted: tuple[bytes, ...]


@dataclass(frozen=True)
class RekeyRecipient:
    """One explicit fresh-epoch recipient; no key material is represented."""

    node_id: bytes
    access: RekeyAccess
    topics: tuple[str, ...] = ()

    @classmethod
    def route_only(cls, node_id: bytes) -> RekeyRecipient:
        return cls(bytes(node_id), RekeyAccess.ROUTE_ONLY)

    @classmethod
    def read_topics(cls, node_id: bytes, topics) -> RekeyRecipient:
        return cls(bytes(node_id), RekeyAccess.READ_TOPICS, tuple(topics))


@dataclass(frozen=True)
class ScopeRekeyReceipt:
    epoch: int
    registry_generation: int
    recipient_count: int
    control_sequence: int


@dataclass(frozen=True)
class BridgeAuthorizationPolicy:
    topics: tuple[str, ...]
    allowed_priorities: PriorityMask
    max_total_hops: int


@dataclass(frozen=True)
class BridgeNarrowingPolicy:
    # Empty topics retain all topics still permitted by the authority object.
    topics: tuple[str, ...]
    allowed_priorities: PriorityMask


@dataclass(frozen=True)
class BridgeAuthorizationResult:
    authorization_id: bytes
    generation: int
    control_sequence: int
    enabled: bool


@dataclass(frozen=True)
class BridgeRouteResult:
    route_handle: bytes
    source_item: bytes
    current_scope: str
    current_route_epoch: int
    hop_count: int
    status: BridgeCommitStatus


@dataclass(frozen=True)
class BridgeAuthorizationStatus:
    authorization_id: bytes
    authority: bytes
    bridge_node: bytes
    source_scope: str
    target_scope: str
    generation: int
    control_sequence: int
    applied: bool
    current: bool
    enabled: bool
    usable: bool
    source_route_epoch: Optional[int]
    target_route_epoch: Optional[int]
    topics: tuple[str, ...]
    allowed_priorities: PriorityMask
    max_total_hops: Optional[int]


@dataclass(frozen=True)
class BridgeRouteStatus:
    route_handle: bytes
    source_item: bytes
    origin_scope: str
    origin_route_epoch: int
    current_scope: str
    current_route_epoch: int
    topic: str
    priority: Priority
    hop_count: int
    active: bool
    live: bool


@dataclass(frozen=True)
class BlobFinish:
    blob_id: bytes
    receipt: PublishReceipt


@dataclass(frozen=True)
class Item:
    item_id: bytes
    publisher: bytes
    data_class: DataClass
    priority: Priority
    causal_counter: int
    event_sequence: Optional[int]
    topic: str
    # Compatibility alias for current_scope.
    scope: str
    origin_scope: str
    current_scope: str
    logical_key: bytes
    payload: bytes
    tombstone: bool


@dataclass(frozen=True)
class Conflict:
    logical_key: bytes
    siblings: tuple[bytes, ...]
    merge_policy: Optional[str]


@dataclass(frozen=True)
class PeerSnapshot:
    peer: bytes
    peer_state: int
    sync_state: int
    last_change_ms: Optional[int]
    detail: Optional[str]


@dataclass(frozen=True)
class Delivery:
    subscription: int
    attempt: int
    item: Item


def _receipt(raw: _Receipt) -> PublishReceipt:
    return PublishReceipt(
        bytes(raw.item_id), bytes(raw.publisher), raw.causal_counter,
        raw.event_sequence if raw.has_event_sequence else None,
        Priority(raw.effective_priority),
    )


def _batch_result(result: _Handle) -> BatchPublishResult:
    try:
        item_count = _c.c_size_t()
        _check(_lib.aster_batch_result_len(result, _c.byref(item_count)))
        receipts = []
        for index in range(item_count.value):
            output = _versioned(_Receipt())
            _check(_lib.aster_batch_result_get(result, index, _c.byref(output)))
            receipts.append(_receipt(output))

        eviction_count = _c.c_size_t()
        _check(_lib.aster_batch_result_evicted_len(
            result, _c.byref(eviction_count),
        ))
        evicted = []
        for index in range(eviction_count.value):
            output = _versioned(_ItemId())
            _check(_lib.aster_batch_result_evicted_get(
                result, index, _c.byref(output),
            ))
            evicted.append(bytes(output.bytes))
        return BatchPublishResult(tuple(receipts), tuple(evicted))
    finally:
        _check(_lib.aster_batch_result_close(_c.byref(result)))


def _item_value(raw: _Item) -> Item:
    return Item(
        bytes(raw.item_id), bytes(raw.publisher), DataClass(raw.data_class),
        Priority(raw.priority), raw.causal_counter,
        raw.event_sequence if raw.has_event_sequence else None,
        _copy(raw.topic).decode(), _copy(raw.scope).decode(),
        _copy(raw.origin_scope).decode(), _copy(raw.current_scope).decode(),
        _copy(raw.logical_key), _copy(raw.payload), bool(raw.tombstone),
    )


def _id32(value, label: str) -> bytes:
    raw = bytes(value)
    if len(raw) != 32:
        raise ValueError(f"{label} must be exactly 32 bytes")
    return raw


def _bridge_priority_mask(value) -> PriorityMask:
    try:
        mask = PriorityMask(value)
    except (TypeError, ValueError) as error:
        raise ValueError("bridge priority mask is invalid") from error
    if int(mask) == 0 or int(mask) & ~int(PriorityMask.ALL):
        raise ValueError(
            "bridge priority mask must explicitly select bits 0 through 3"
        )
    return mask


def _bridge_topic_array(topics, *, required: bool):
    values = tuple(topics)
    if required and not values:
        raise ValueError("bridge policy requires at least one topic")
    if len(values) > 128:
        raise ValueError("bridge policy topics exceed 128 entries")
    native_values = []
    storage = []
    for index, topic in enumerate(values):
        _bounded_name(topic, f"bridge topics[{index}]")
        native, keep = _input(topic)
        native_values.append(native)
        storage.append(keep)
    array = (_Bytes * len(native_values))(*native_values) if native_values else None
    pointer = _c.cast(array, _c.POINTER(_Bytes)) if array is not None else None
    return values, pointer, array, storage


def _bridge_authorization_result(raw: _BridgeAuthorizationResult) -> BridgeAuthorizationResult:
    return BridgeAuthorizationResult(
        bytes(raw.id), raw.generation, raw.control_sequence, bool(raw.enabled),
    )


def _bridge_route_result(raw: _BridgeRouteResult) -> BridgeRouteResult:
    return BridgeRouteResult(
        bytes(raw.handle), bytes(raw.source_item), _copy(raw.current_scope).decode(),
        raw.current_route_epoch, raw.hop_count, BridgeCommitStatus(raw.commit_status),
    )


def _decode_bridge_topics(raw: _Owned, count: int) -> tuple[str, ...]:
    if not 0 <= count <= 128:
        raise AsterError(255, "native bridge topic count exceeds 128")
    encoded = memoryview(_copy(raw))
    topics = []
    offset = 0
    for _ in range(count):
        if offset + 2 > len(encoded):
            raise AsterError(255, "native bridge topic list is truncated")
        length = int.from_bytes(encoded[offset:offset + 2], "big")
        offset += 2
        if not length or offset + length > len(encoded):
            raise AsterError(255, "native bridge topic length is invalid")
        topics.append(bytes(encoded[offset:offset + length]).decode())
        offset += length
    if offset != len(encoded):
        raise AsterError(255, "native bridge topic list has trailing bytes")
    return tuple(topics)


def _bridge_authorization_status(raw: _BridgeAuthorizationStatus) -> BridgeAuthorizationStatus:
    return BridgeAuthorizationStatus(
        bytes(raw.id), bytes(raw.authority), bytes(raw.bridge_node),
        _copy(raw.source_scope).decode(), _copy(raw.target_scope).decode(),
        raw.generation, raw.control_sequence, bool(raw.applied), bool(raw.current),
        bool(raw.enabled), bool(raw.usable),
        raw.source_route_epoch if raw.has_source_route_epoch else None,
        raw.target_route_epoch if raw.has_target_route_epoch else None,
        _decode_bridge_topics(raw.topics, raw.topic_count),
        PriorityMask(raw.allowed_priority_mask),
        raw.max_total_hops if raw.has_max_total_hops else None,
    )


def _bridge_route_status(raw: _BridgeRouteStatus) -> BridgeRouteStatus:
    return BridgeRouteStatus(
        bytes(raw.handle), bytes(raw.source_item), _copy(raw.origin_scope).decode(),
        raw.origin_route_epoch, _copy(raw.current_scope).decode(),
        raw.current_route_epoch, _copy(raw.topic).decode(), Priority(raw.priority),
        raw.hop_count, bool(raw.active), bool(raw.live),
    )


class BridgeEnrollment:
    """Process-local move-only enrollment consumed by authority enable."""

    def __init__(self, handle: _Handle):
        self._handle = handle
        self._lock = _threading.RLock()

    @property
    def closed(self) -> bool:
        return not bool(self._handle.value)

    def close(self) -> None:
        with self._lock:
            if self._handle.value:
                _check(_lib.aster_bridge_enrollment_close(_c.byref(self._handle)))

    def __enter__(self) -> BridgeEnrollment:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


class Subscription:
    """Durable at-least-once application subscription."""

    def __init__(self, node: Node, identifier: int):
        self._node = node
        self.id = identifier

    def poll(self, limit: int = 64) -> list[Delivery]:
        return self._node._poll(self.id, limit)

    def acknowledge(self, item: Delivery | Item | bytes) -> None:
        if isinstance(item, Delivery):
            item_id = item.item.item_id
        elif isinstance(item, Item):
            item_id = item.item_id
        else:
            item_id = bytes(item)
        self._node._acknowledge(self.id, item_id)


class BlobWriter(_io.RawIOBase):
    """Bounded streaming Blob writer; call finish before close."""

    def __init__(self, node: Node, handle: _Handle):
        super().__init__()
        self._node = node
        self._handle = handle

    def writable(self) -> bool:
        return True

    def write(self, value) -> int:
        if self.closed or not self._handle.value:
            raise ValueError("I/O operation on closed Blob writer")
        raw = memoryview(value).cast("B").tobytes()
        native, storage = _input(raw); _ = storage
        with self._node._lock:
            _check(_lib.aster_blob_writer_write(self._handle, native))
        return len(raw)

    def finish(self) -> BlobFinish:
        if self.closed or not self._handle.value:
            raise ValueError("I/O operation on closed Blob writer")
        with self._node._lock:
            output = _versioned(_BlobFinish())
            _check(_lib.aster_blob_writer_finish(self._handle, _c.byref(output)))
            return BlobFinish(bytes(output.blob_id), _receipt(output.receipt))

    def close(self) -> None:
        if getattr(self, "_handle", None) is not None and self._handle.value:
            with self._node._lock:
                _check(_lib.aster_blob_writer_close(_c.byref(self._handle)))
        super().close()


class BlobReader(_io.RawIOBase):
    """Incremental authenticated Blob reader."""

    def __init__(self, node: Node, handle: _Handle):
        super().__init__()
        self._node = node
        self._handle = handle

    def readable(self) -> bool:
        return True

    def readinto(self, output) -> int:
        if self.closed or not self._handle.value:
            raise ValueError("I/O operation on closed Blob reader")
        view = memoryview(output)
        if view.readonly:
            raise TypeError("Blob reader output must be writable")
        view = view.cast("B")
        if not view.c_contiguous:
            raise TypeError("Blob reader output must be contiguous")
        if not view:
            return 0
        storage = (_c.c_uint8 * len(view)).from_buffer(view)
        count = _c.c_size_t()
        with self._node._lock:
            _check(_lib.aster_blob_reader_read(
                self._handle, _c.cast(storage, _c.POINTER(_c.c_uint8)),
                len(view), _c.byref(count),
            ))
        return count.value

    def close(self) -> None:
        if getattr(self, "_handle", None) is not None and self._handle.value:
            with self._node._lock:
                _check(_lib.aster_blob_reader_close(_c.byref(self._handle)))
        super().close()


class Node:
    """Thread-safe, synchronous, offline-first mesh node."""

    def __init__(self, store_path: str, provisioning_bundle: bytes):
        self._lock = _threading.RLock()
        self._handle = _Handle()
        options = _Options()
        _check(_lib.aster_node_options_init(_c.byref(options)))
        options.store_path, path_storage = _input(store_path)
        options.provisioning_bundle, bundle_storage = _input(provisioning_bundle)
        _ = (path_storage, bundle_storage)
        _check(_lib.aster_node_open(_c.byref(options), _c.byref(self._handle)))

    def __enter__(self) -> Node:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _active(self) -> _Handle:
        if not self._handle.value:
            raise AsterError(5, "node is closed")
        return self._handle

    def close(self) -> None:
        with self._lock:
            if self._handle.value:
                _check(_lib.aster_node_close(_c.byref(self._handle)))

    def zeroize(self) -> None:
        with self._lock:
            if not self._handle.value:
                raise AsterError(5, "node is closed")
            _check(_lib.aster_node_zeroize(_c.byref(self._handle)))

    def publish(self, data_class: DataClass, topic: str, scope: str, payload: bytes,
                *, logical_key: bytes = b"", priority: Priority = Priority.ROUTINE,
                ttl_ms: Optional[int] = None, tombstone: bool = False) -> PublishReceipt:
        with self._lock:
            request = _versioned(_Publish())
            request.data_class, request.priority = int(data_class), int(priority)
            request.topic, a = _input(topic); request.scope, b = _input(scope)
            request.logical_key, c = _input(logical_key); request.payload, d = _input(payload)
            _ = (a, b, c, d)
            request.has_ttl = ttl_ms is not None
            request.ttl_ms = ttl_ms or 0
            request.tombstone = tombstone
            output = _versioned(_Receipt())
            _check(_lib.aster_node_publish(self._active(), _c.byref(request), _c.byref(output)))
            return _receipt(output)

    def publish_batch(
        self, items, policy: BatchPublicationPolicy = BatchPublicationPolicy.RETAINED_DUAL,
    ) -> BatchPublishResult:
        """Atomically publish 2-64 ordered, same-route, non-Blob items."""
        values = tuple(items)
        if not 2 <= len(values) <= 64:
            raise ValueError("batch must contain between 2 and 64 items")
        try:
            selected_policy = BatchPublicationPolicy(policy)
        except (TypeError, ValueError) as error:
            raise ValueError("unknown batch publication policy") from error

        native_items = (_Publish * len(values))()
        keepalive = [native_items]
        for index, item in enumerate(values):
            if not isinstance(item, BatchPublishItem):
                raise TypeError(f"items[{index}] must be a BatchPublishItem")
            native = native_items[index]
            _versioned(native)
            native.data_class = int(item.data_class)
            native.priority = int(item.priority)
            native.topic, topic_storage = _input(item.topic)
            native.scope, scope_storage = _input(item.scope)
            native.logical_key, key_storage = _input(item.logical_key)
            native.payload, payload_storage = _input(item.payload)
            native.has_ttl = item.ttl_ms is not None
            native.ttl_ms = item.ttl_ms or 0
            native.tombstone = item.tombstone
            keepalive.extend((topic_storage, scope_storage, key_storage, payload_storage))

        with self._lock:
            request = _versioned(_PublishBatch())
            request.items = _c.cast(native_items, _c.POINTER(_Publish))
            request.item_count = len(native_items)
            request.policy = int(selected_policy)
            result = _Handle()
            _ = keepalive
            _check(_lib.aster_node_publish_batch(
                self._active(), _c.byref(request), _c.byref(result),
            ))
            return _batch_result(result)

    def rekey_scope(self, signed_public_registry: bytes,
                    minimum_registry_generation: int, scope: str, new_epoch: int,
                    recipients: list[RekeyRecipient]) -> ScopeRekeyReceipt:
        """Durably publish an authority-only fresh epoch from an opaque registry."""
        registry = bytes(signed_public_registry)
        if not 1 <= len(registry) <= _MAX_REKEY_REGISTRY_BYTES:
            raise ValueError("signed public registry must be between 1 byte and 16 MiB")
        _bounded_u64(minimum_registry_generation, "minimum registry generation")
        _bounded_u64(new_epoch, "new epoch", nonzero=True)
        _bounded_name(scope, "scope")
        recipient_values = tuple(recipients)
        if not 1 <= len(recipient_values) <= _MAX_REKEY_RECIPIENTS:
            raise ValueError("rekey recipients must contain between 1 and 128 entries")

        native_recipients = (_RekeyRecipient * len(recipient_values))()
        keepalive = [native_recipients]
        for index, recipient in enumerate(recipient_values):
            if not isinstance(recipient, RekeyRecipient):
                raise TypeError(f"recipients[{index}] must be a RekeyRecipient")
            node_id = bytes(recipient.node_id)
            if len(node_id) != 32:
                raise ValueError(f"recipients[{index}].node_id must be 32 bytes")
            try:
                access = RekeyAccess(recipient.access)
            except ValueError as error:
                raise ValueError(f"recipients[{index}].access is unknown") from error
            topics = tuple(recipient.topics)
            if access is RekeyAccess.ROUTE_ONLY and topics:
                raise ValueError(f"recipients[{index}] route-only access must not include topics")
            if access is RekeyAccess.READ_TOPICS and not 1 <= len(topics) <= _MAX_REKEY_TOPICS:
                raise ValueError(
                    f"recipients[{index}] read-topics access requires 1 to 128 topics"
                )

            native = native_recipients[index]
            _versioned(native)
            native.node_id[:] = node_id
            native.access = int(access)
            if topics:
                topic_values = []
                topic_storage = []
                for topic_index, topic in enumerate(topics):
                    _bounded_name(topic, f"recipients[{index}].topics[{topic_index}]")
                    value, storage = _input(topic)
                    topic_values.append(value)
                    topic_storage.append(storage)
                topic_array = (_Bytes * len(topic_values))(*topic_values)
                native.topics = _c.cast(topic_array, _c.POINTER(_Bytes))
                native.topic_count = len(topic_values)
                keepalive.extend((topic_array, *topic_storage))

        with self._lock:
            request = _versioned(_RekeyRequest())
            request.signed_public_registry, registry_storage = _input(registry)
            request.scope, scope_storage = _input(scope)
            request.minimum_registry_generation = minimum_registry_generation
            request.new_epoch = new_epoch
            request.recipients = _c.cast(native_recipients, _c.POINTER(_RekeyRecipient))
            request.recipient_count = len(native_recipients)
            keepalive.extend((registry_storage, scope_storage)); _ = keepalive
            output = _versioned(_RekeyReceipt())
            _check(_lib.aster_node_rekey_scope(
                self._active(), _c.byref(request), _c.byref(output),
            ))
            return ScopeRekeyReceipt(
                output.epoch, output.registry_generation,
                output.recipient_count, output.control_sequence,
            )

    def blob_writer(self, topic: str, scope: str, *,
                    priority: Priority = Priority.ROUTINE,
                    ttl_ms: Optional[int] = None, chunk_size: int = 0,
                    media_type: Optional[str] = None,
                    schema_id: bytes = b"") -> BlobWriter:
        with self._lock:
            options = _BlobPublishOptions()
            _check(_lib.aster_blob_publish_options_init(_c.byref(options)))
            options.topic, a = _input(topic); options.scope, b = _input(scope)
            options.media_type, c = _input(media_type)
            options.schema_id, d = _input(schema_id); _ = (a, b, c, d)
            options.priority = int(priority)
            if chunk_size:
                options.chunk_size = chunk_size
            options.has_ttl = ttl_ms is not None
            options.ttl_ms = ttl_ms or 0
            handle = _Handle()
            _check(_lib.aster_node_blob_writer_open(
                self._active(), _c.byref(options), _c.byref(handle),
            ))
            return BlobWriter(self, handle)

    def publish_blob_batch(
        self, writers, policy: BatchPublicationPolicy = BatchPublicationPolicy.RETAINED_DUAL,
    ) -> BatchPublishResult:
        """Finalize and atomically publish 2-64 distinct Blob writers."""
        values = tuple(writers)
        if not 2 <= len(values) <= 64:
            raise ValueError("Blob batch must contain between 2 and 64 writers")
        try:
            selected_policy = BatchPublicationPolicy(policy)
        except (TypeError, ValueError) as error:
            raise ValueError("unknown batch publication policy") from error
        if len({id(writer) for writer in values}) != len(values):
            raise ValueError("Blob batch contains a duplicate writer")
        for index, writer in enumerate(values):
            if not isinstance(writer, BlobWriter):
                raise TypeError(f"writers[{index}] must be a BlobWriter")
            if writer._node is not self:
                raise ValueError(f"writers[{index}] belongs to another node")

        with self._lock:
            native_writers = (_Handle * len(values))()
            seen_handles = set()
            for index, writer in enumerate(values):
                if writer.closed or not writer._handle.value:
                    raise ValueError(f"writers[{index}] is closed")
                if writer._handle.value in seen_handles:
                    raise ValueError("Blob batch contains a duplicate native writer handle")
                seen_handles.add(writer._handle.value)
                native_writers[index] = writer._handle
            request = _versioned(_BlobPublishBatch())
            request.writers = _c.cast(native_writers, _c.POINTER(_Handle))
            request.writer_count = len(native_writers)
            request.policy = int(selected_policy)
            result = _Handle()
            _check(_lib.aster_node_publish_blob_batch(
                self._active(), _c.byref(request), _c.byref(result),
            ))
            return _batch_result(result)

    def blob_reader(self, topic: str, scope: str, blob_id: bytes) -> BlobReader:
        if len(blob_id) != 32:
            raise ValueError("Blob identifier must be 32 bytes")
        with self._lock:
            request = _versioned(_BlobReadRequest())
            request.topic, a = _input(topic); request.scope, b = _input(scope)
            _ = (a, b); request.blob_id[:] = blob_id
            handle = _Handle()
            _check(_lib.aster_node_blob_reader_open(
                self._active(), _c.byref(request), _c.byref(handle),
            ))
            return BlobReader(self, handle)

    def query(self, *, topic: Optional[str] = None, scope: Optional[str] = None,
              logical_key: Optional[bytes] = None, data_class: Optional[DataClass] = None,
              include_descendants: bool = False, include_recoverable: bool = False,
              include_tombstones: bool = False, limit: int = 0) -> list[Item]:
        with self._lock:
            request = _versioned(_QueryRequest())
            request.topic, a = _input(topic); request.scope, b = _input(scope)
            request.logical_key, c = _input(logical_key); _ = (a, b, c)
            request.data_class = _ANY_CLASS if data_class is None else int(data_class)
            request.include_descendant_scopes = include_descendants
            request.include_recoverable_versions = include_recoverable
            request.include_tombstones = include_tombstones; request.limit = limit
            result = _Handle()
            _check(_lib.aster_node_query(self._active(), _c.byref(request), _c.byref(result)))
            try:
                count = _c.c_size_t()
                _check(_lib.aster_query_len(result, _c.byref(count)))
                return [self._query_item(result, index) for index in range(count.value)]
            finally:
                _check(_lib.aster_query_close(_c.byref(result)))

    def _query_item(self, result: _Handle, index: int) -> Item:
        raw = _versioned(_Item())
        _check(_lib.aster_query_get(result, index, _c.byref(raw)))
        try:
            return _item_value(raw)
        finally:
            _check(_lib.aster_item_free(_c.byref(raw)))

    def subscribe(self, topic: str, scope: str, *, data_class: Optional[DataClass] = None,
                  include_descendants: bool = False) -> Subscription:
        with self._lock:
            request = _versioned(_Subscribe())
            request.topic, a = _input(topic); request.scope, b = _input(scope); _ = (a, b)
            request.data_class = _ANY_CLASS if data_class is None else int(data_class)
            request.include_descendant_scopes = include_descendants
            identifier = _c.c_uint64()
            _check(_lib.aster_node_subscribe(self._active(), _c.byref(request), _c.byref(identifier)))
            return Subscription(self, identifier.value)

    def _poll(self, subscription: int, limit: int) -> list[Delivery]:
        with self._lock:
            request = _versioned(_Poll())
            request.subscription = subscription; request.limit = limit
            result = _Handle()
            _check(_lib.aster_node_poll(self._active(), _c.byref(request), _c.byref(result)))
            try:
                count = _c.c_size_t(); _check(_lib.aster_deliveries_len(result, _c.byref(count)))
                return [self._delivery(result, index) for index in range(count.value)]
            finally:
                _check(_lib.aster_deliveries_close(_c.byref(result)))

    def _delivery(self, result: _Handle, index: int) -> Delivery:
        raw = _versioned(_Delivery())
        _check(_lib.aster_deliveries_get(result, index, _c.byref(raw)))
        try:
            return Delivery(raw.subscription, raw.attempt, _item_value(raw.item))
        finally:
            _check(_lib.aster_delivery_free(_c.byref(raw)))

    def _acknowledge(self, subscription: int, item_id: bytes) -> None:
        if len(item_id) != 32:
            raise ValueError("item identifier must be 32 bytes")
        with self._lock:
            request = _versioned(_Ack())
            request.subscription = subscription; request.item_id[:] = item_id
            _check(_lib.aster_node_acknowledge(self._active(), _c.byref(request)))

    def conflicts(self, **filters) -> list[Conflict]:
        with self._lock:
            request, keep = self._query_request(**filters)
            _ = keep
            result = _Handle()
            _check(_lib.aster_node_conflicts(self._active(), _c.byref(request), _c.byref(result)))
            try:
                count = _c.c_size_t(); _check(_lib.aster_conflicts_len(result, _c.byref(count)))
                return [self._conflict(result, index) for index in range(count.value)]
            finally:
                _check(_lib.aster_conflicts_close(_c.byref(result)))

    def _query_request(self, *, topic=None, scope=None, logical_key=None,
                       data_class=None, include_descendants=False,
                       include_recoverable=False, include_tombstones=False, limit=0):
        request = _versioned(_QueryRequest())
        request.topic, a = _input(topic); request.scope, b = _input(scope)
        request.logical_key, c = _input(logical_key)
        request.data_class = _ANY_CLASS if data_class is None else int(data_class)
        request.include_descendant_scopes = include_descendants
        request.include_recoverable_versions = include_recoverable
        request.include_tombstones = include_tombstones; request.limit = limit
        return request, (a, b, c)

    def _conflict(self, result: _Handle, index: int) -> Conflict:
        raw = _versioned(_Conflict())
        _check(_lib.aster_conflicts_get(result, index, _c.byref(raw)))
        try:
            sibling_data = _copy(raw.sibling_ids)
            siblings = tuple(sibling_data[i:i + 32] for i in range(0, len(sibling_data), 32))
            policy = _copy(raw.merge_policy).decode() if raw.has_merge_policy else None
            return Conflict(_copy(raw.logical_key), siblings, policy)
        finally:
            _check(_lib.aster_conflict_free(_c.byref(raw)))

    def resolve(self, topic: str, scope: str, logical_key: bytes,
                conflict: Conflict, payload: bytes, *,
                priority: Priority = Priority.ROUTINE,
                ttl_ms: Optional[int] = None) -> PublishReceipt:
        with self._lock:
            request = _versioned(_Resolve())
            request.topic, a = _input(topic); request.scope, b = _input(scope)
            request.logical_key, c = _input(logical_key)
            request.expected_sibling_ids, d = _input(b"".join(conflict.siblings))
            request.payload, e = _input(payload); _ = (a, b, c, d, e)
            request.priority = int(priority); request.has_ttl = ttl_ms is not None
            request.ttl_ms = ttl_ms or 0
            output = _versioned(_Receipt())
            _check(_lib.aster_node_resolve(self._active(), _c.byref(request), _c.byref(output)))
            return _receipt(output)

    @property
    def emission_threshold(self) -> EmissionThreshold:
        with self._lock:
            output = _c.c_uint32()
            _check(_lib.aster_node_get_emission(self._active(), _c.byref(output)))
            return EmissionThreshold(output.value)

    @emission_threshold.setter
    def emission_threshold(self, value: EmissionThreshold) -> None:
        with self._lock:
            _check(_lib.aster_node_set_emission(self._active(), int(value)))

    def peer_status(self, peer: bytes) -> PeerSnapshot:
        if len(peer) != 32:
            raise ValueError("peer must be 32 bytes")
        with self._lock:
            request = _versioned(_PeerRequest()); request.peer[:] = peer
            raw = _versioned(_PeerSnapshot())
            _check(_lib.aster_node_peer_status(self._active(), _c.byref(request), _c.byref(raw)))
            try:
                return self._peer_value(raw)
            finally:
                _check(_lib.aster_peer_snapshot_free(_c.byref(raw)))

    def peers(self) -> list[PeerSnapshot]:
        with self._lock:
            result = _Handle(); _check(_lib.aster_node_peers(self._active(), _c.byref(result)))
            try:
                count = _c.c_size_t(); _check(_lib.aster_peers_len(result, _c.byref(count)))
                values = []
                for index in range(count.value):
                    raw = _versioned(_PeerSnapshot())
                    _check(_lib.aster_peers_get(result, index, _c.byref(raw)))
                    try: values.append(self._peer_value(raw))
                    finally: _check(_lib.aster_peer_snapshot_free(_c.byref(raw)))
                return values
            finally:
                _check(_lib.aster_peers_close(_c.byref(result)))

    @staticmethod
    def _peer_value(raw: _PeerSnapshot) -> PeerSnapshot:
        return PeerSnapshot(
            bytes(raw.peer), raw.peer_state, raw.sync_state,
            raw.last_change_ms if raw.has_last_change else None,
            _copy(raw.detail).decode() if raw.has_detail else None,
        )

    def create_bridge_enrollment(
        self, source_scope: str, source_route_epoch: int,
        target_scope: str, target_route_epoch: int,
    ) -> BridgeEnrollment:
        _bounded_name(source_scope, "source scope")
        _bounded_name(target_scope, "target scope")
        _bounded_u64(source_route_epoch, "source route epoch", nonzero=True)
        _bounded_u64(target_route_epoch, "target route epoch", nonzero=True)
        with self._lock:
            request = _versioned(_BridgeEnrollmentRequest())
            request.source_scope, a = _input(source_scope)
            request.target_scope, b = _input(target_scope)
            request.source_route_epoch = source_route_epoch
            request.target_route_epoch = target_route_epoch
            _ = (a, b)
            handle = _Handle()
            _check(_lib.aster_node_bridge_enrollment_create(
                self._active(), _c.byref(request), _c.byref(handle),
            ))
            return BridgeEnrollment(handle)

    def enable_bridge(
        self, enrollment: BridgeEnrollment, policy: BridgeAuthorizationPolicy,
    ) -> BridgeAuthorizationResult:
        if not isinstance(enrollment, BridgeEnrollment):
            raise TypeError("enrollment must be a BridgeEnrollment")
        if not isinstance(policy, BridgeAuthorizationPolicy):
            raise TypeError("policy must be a BridgeAuthorizationPolicy")
        mask = _bridge_priority_mask(policy.allowed_priorities)
        if not isinstance(policy.max_total_hops, int) or isinstance(policy.max_total_hops, bool):
            raise ValueError("bridge maximum total hops must be between 1 and 8")
        if not 1 <= policy.max_total_hops <= 8:
            raise ValueError("bridge maximum total hops must be between 1 and 8")
        _, topics, topic_array, storage = _bridge_topic_array(
            policy.topics, required=True,
        )
        _ = (topic_array, storage)
        with enrollment._lock, self._lock:
            if enrollment.closed:
                raise AsterError(5, "bridge enrollment is closed or consumed")
            native = _versioned(_BridgeEnablePolicy())
            native.topics = topics
            native.topic_count = len(policy.topics)
            native.allowed_priority_mask = int(mask)
            native.max_total_hops = policy.max_total_hops
            output = _versioned(_BridgeAuthorizationResult())
            status = _lib.aster_node_bridge_enable(
                self._active(), _c.byref(enrollment._handle),
                _c.byref(native), _c.byref(output),
            )
            _check(status)
            return _bridge_authorization_result(output)

    def disable_bridge(
        self, bridge_node: bytes, source_scope: str, target_scope: str,
    ) -> BridgeAuthorizationResult:
        bridge_node = _id32(bridge_node, "bridge node")
        _bounded_name(source_scope, "source scope")
        _bounded_name(target_scope, "target scope")
        with self._lock:
            request = _versioned(_BridgeDisableRequest())
            request.bridge_node[:] = bridge_node
            request.source_scope, a = _input(source_scope)
            request.target_scope, b = _input(target_scope)
            _ = (a, b)
            output = _versioned(_BridgeAuthorizationResult())
            _check(_lib.aster_node_bridge_disable(
                self._active(), _c.byref(request), _c.byref(output),
            ))
            return _bridge_authorization_result(output)

    def bridge_item(
        self, source_item: bytes, authorization_id: bytes,
        policy: BridgeNarrowingPolicy,
    ) -> BridgeRouteResult:
        source_item = _id32(source_item, "source item")
        authorization_id = _id32(authorization_id, "bridge authorization identifier")
        if not isinstance(policy, BridgeNarrowingPolicy):
            raise TypeError("policy must be a BridgeNarrowingPolicy")
        mask = _bridge_priority_mask(policy.allowed_priorities)
        _, topics, topic_array, storage = _bridge_topic_array(
            policy.topics, required=False,
        )
        _ = (topic_array, storage)
        with self._lock:
            request = _versioned(_BridgeItemRequest())
            request.source_item[:] = source_item
            request.authorization_id[:] = authorization_id
            request.topics = topics
            request.topic_count = len(policy.topics)
            request.allowed_priority_mask = int(mask)
            output = _versioned(_BridgeRouteResult())
            _check(_lib.aster_node_bridge_item(
                self._active(), _c.byref(request), _c.byref(output),
            ))
            try:
                return _bridge_route_result(output)
            finally:
                _check(_lib.aster_bridge_route_result_free(_c.byref(output)))

    def extend_bridge_route(
        self, route_handle: bytes, authorization_id: bytes,
        policy: BridgeNarrowingPolicy,
    ) -> BridgeRouteResult:
        route_handle = _id32(route_handle, "bridge route handle")
        authorization_id = _id32(authorization_id, "bridge authorization identifier")
        if not isinstance(policy, BridgeNarrowingPolicy):
            raise TypeError("policy must be a BridgeNarrowingPolicy")
        mask = _bridge_priority_mask(policy.allowed_priorities)
        _, topics, topic_array, storage = _bridge_topic_array(
            policy.topics, required=False,
        )
        _ = (topic_array, storage)
        with self._lock:
            request = _versioned(_BridgeExtendRequest())
            request.route_handle[:] = route_handle
            request.authorization_id[:] = authorization_id
            request.topics = topics
            request.topic_count = len(policy.topics)
            request.allowed_priority_mask = int(mask)
            output = _versioned(_BridgeRouteResult())
            _check(_lib.aster_node_bridge_extend(
                self._active(), _c.byref(request), _c.byref(output),
            ))
            try:
                return _bridge_route_result(output)
            finally:
                _check(_lib.aster_bridge_route_result_free(_c.byref(output)))

    @staticmethod
    def _bridge_status_request(identifier: bytes, label: str) -> _BridgeStatusRequest:
        request = _versioned(_BridgeStatusRequest())
        request.id[:] = _id32(identifier, label)
        return request

    @staticmethod
    def _bridge_page_request(after: Optional[bytes], limit: int) -> _BridgePageRequest:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= 4096:
            raise ValueError("bridge page limit must be between zero and 4096")
        request = _versioned(_BridgePageRequest())
        request.limit = limit
        if after is not None:
            request.after[:] = _id32(after, "bridge page cursor")
            request.has_after = 1
        return request

    def bridge_authorization_status(
        self, authorization_id: bytes,
    ) -> BridgeAuthorizationStatus:
        with self._lock:
            request = self._bridge_status_request(
                authorization_id, "bridge authorization identifier",
            )
            raw = _versioned(_BridgeAuthorizationStatus())
            _check(_lib.aster_node_bridge_authorization_status(
                self._active(), _c.byref(request), _c.byref(raw),
            ))
            try:
                return _bridge_authorization_status(raw)
            finally:
                _check(_lib.aster_bridge_authorization_status_free(_c.byref(raw)))

    def bridge_authorizations(
        self, *, after: Optional[bytes] = None, limit: int = 64,
    ) -> list[BridgeAuthorizationStatus]:
        with self._lock:
            request = self._bridge_page_request(after, limit)
            page = _Handle()
            _check(_lib.aster_node_bridge_authorizations(
                self._active(), _c.byref(request), _c.byref(page),
            ))
            try:
                count = _c.c_size_t()
                _check(_lib.aster_bridge_authorizations_len(page, _c.byref(count)))
                values = []
                for index in range(count.value):
                    raw = _versioned(_BridgeAuthorizationStatus())
                    _check(_lib.aster_bridge_authorizations_get(
                        page, index, _c.byref(raw),
                    ))
                    try:
                        values.append(_bridge_authorization_status(raw))
                    finally:
                        _check(_lib.aster_bridge_authorization_status_free(_c.byref(raw)))
                return values
            finally:
                _check(_lib.aster_bridge_authorizations_close(_c.byref(page)))

    def bridge_route_status(self, route_handle: bytes) -> BridgeRouteStatus:
        with self._lock:
            request = self._bridge_status_request(route_handle, "bridge route handle")
            raw = _versioned(_BridgeRouteStatus())
            _check(_lib.aster_node_bridge_route_status(
                self._active(), _c.byref(request), _c.byref(raw),
            ))
            try:
                return _bridge_route_status(raw)
            finally:
                _check(_lib.aster_bridge_route_status_free(_c.byref(raw)))

    def bridge_routes(
        self, *, after: Optional[bytes] = None, limit: int = 64,
    ) -> list[BridgeRouteStatus]:
        with self._lock:
            request = self._bridge_page_request(after, limit)
            page = _Handle()
            _check(_lib.aster_node_bridge_routes(
                self._active(), _c.byref(request), _c.byref(page),
            ))
            try:
                count = _c.c_size_t()
                _check(_lib.aster_bridge_routes_len(page, _c.byref(count)))
                values = []
                for index in range(count.value):
                    raw = _versioned(_BridgeRouteStatus())
                    _check(_lib.aster_bridge_routes_get(page, index, _c.byref(raw)))
                    try:
                        values.append(_bridge_route_status(raw))
                    finally:
                        _check(_lib.aster_bridge_route_status_free(_c.byref(raw)))
                return values
            finally:
                _check(_lib.aster_bridge_routes_close(_c.byref(page)))

    def set_bridge_filters(self, filters: list[tuple[str, str, Optional[str], Priority]]) -> None:
        with self._lock:
            array = (_BridgeFilter * len(filters))()
            keep = []
            for index, (source, target, topic, minimum) in enumerate(filters):
                _versioned(array[index])
                array[index].from_scope, a = _input(source)
                array[index].to_scope, b = _input(target)
                array[index].topic, c = _input(topic)
                array[index].minimum_priority = int(minimum); keep.extend((a, b, c))
            pointer = array if filters else None; _ = keep
            _check(_lib.aster_node_set_bridge_filters(self._active(), pointer, len(filters)))


__all__ = [
    "ABI_VERSION", "PROTOCOL_VERSION", "REPLICATION_WIRE_VERSION",
    "DEFAULT_SEMANTIC_VERSION", "HIGHEST_SUPPORTED_SEMANTIC_VERSION",
    "AsterError", "BatchPublicationPolicy", "BatchPublishItem",
    "BatchPublishResult", "BlobFinish", "BlobReader", "BlobWriter",
    "BridgeAuthorizationPolicy", "BridgeAuthorizationResult",
    "BridgeAuthorizationStatus", "BridgeCommitStatus", "BridgeEnrollment",
    "BridgeNarrowingPolicy", "BridgeRouteResult", "BridgeRouteStatus",
    "Conflict", "DataClass",
    "Delivery", "EmissionThreshold", "Item", "Node", "PeerSnapshot", "Priority",
    "PriorityMask", "PublishReceipt", "RekeyAccess", "RekeyRecipient",
    "ScopeRekeyReceipt", "Subscription",
]
