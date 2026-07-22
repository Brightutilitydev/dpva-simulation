from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional
import struct
import hashlib
import hmac as hmac_mod


class MessageType(IntEnum):
    PATH_CLAIM = 0x01
    PROBE = 0x02
    PROBE_ACK = 0x03
    VERIFICATION_TOKEN = 0x04
    CHALLENGE = 0x05
    CHALLENGE_RESPONSE = 0x06
    SKETCH_SNAPSHOT = 0x07
    AUDIT_SUBMISSION = 0x08


class AnomalyType(IntEnum):
    NONE = 0
    TAG_CHAIN_MISMATCH = 1
    SKETCH_DEVIATION = 2
    UNEXPECTED_NODE = 3
    MISSING_NODE = 4
    SEQUENCE_GAP = 5
    REPLAY_DETECTED = 6
    PATH_CLAIM_EXPIRED = 7


@dataclass
class PathClaim:
    path_id: int
    claimant_id: int
    timestamp: int
    ttl: int
    hop_count: int
    nonce: int
    path: list[int]
    signature: bytes = b""

    def serialize(self) -> bytes:
        buf = struct.pack("!IIIIBB", self.path_id, self.claimant_id,
                          self.timestamp, self.ttl, self.hop_count, self.nonce)
        for node_id in self.path:
            buf += struct.pack("!I", node_id)
        buf += struct.pack("!H", len(self.signature))
        buf += self.signature
        return buf

    @classmethod
    def deserialize(cls, data: bytes) -> "PathClaim":
        off = struct.calcsize("!IIIIBB")
        path_id, claimant_id, timestamp, ttl, hop_count, nonce = struct.unpack_from("!IIIIBB", data, 0)
        path = []
        for i in range(hop_count):
            node_id = struct.unpack_from("!I", data, off)[0]
            path.append(node_id)
            off += 4
        sig_len = struct.unpack_from("!H", data, off)[0]
        off += 2
        signature = data[off:off + sig_len]
        return cls(path_id, claimant_id, timestamp, ttl, hop_count, nonce, path, signature)

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "claimant_id": self.claimant_id,
            "timestamp": self.timestamp,
            "ttl": self.ttl,
            "hop_count": self.hop_count,
            "nonce": self.nonce,
            "path": self.path,
            "signature_hex": self.signature.hex(),
        }

    def sign(self, private_key: bytes):
        import nacl.bindings
        self.signature = nacl.bindings.crypto_sign(self._digest(), private_key)

    def verify(self, public_key: bytes) -> bool:
        import nacl.bindings
        try:
            nacl.bindings.crypto_sign_open(self.signature + self._digest(), public_key)
            return True
        except Exception:
            return False

    def _digest(self) -> bytes:
        d = hashlib.sha256()
        d.update(struct.pack("!I", self.path_id))
        d.update(struct.pack("!I", self.claimant_id))
        d.update(struct.pack("!I", self.timestamp))
        d.update(struct.pack("!H", self.ttl))
        d.update(struct.pack("!B", self.hop_count))
        for node_id in self.path:
            d.update(struct.pack("!I", node_id))
        d.update(struct.pack("!B", self.nonce))
        return d.digest()


@dataclass
class Probe:
    path_id: int
    nonce: int
    hop_count: int
    accumulated_tag: bytes = b""

    def serialize(self) -> bytes:
        return struct.pack("!IIB", self.path_id, self.nonce, self.hop_count) + self.accumulated_tag

    @classmethod
    def deserialize(cls, data: bytes) -> "Probe":
        off = struct.calcsize("!IIB")
        path_id, nonce, hop_count = struct.unpack_from("!IIB", data, 0)
        tag = data[off:]
        return cls(path_id, nonce, hop_count, tag)


@dataclass
class ProbeAck:
    path_id: int
    success: bool
    anomaly_type: int = 0
    challenge_nonce: int = 0

    def serialize(self) -> bytes:
        return struct.pack("!IB?I", self.path_id, self.anomaly_type, self.success, self.challenge_nonce)


@dataclass
class VerificationToken:
    path_id: int
    seq_number: int
    node_id: int
    hmac_value: bytes = b""

    def compute(self, key: bytes, nonce: int):
        msg = struct.pack("!III", self.path_id, self.seq_number, self.node_id)
        msg += struct.pack("!I", nonce)
        self.hmac_value = hmac_mod.new(key, msg, hashlib.sha256).digest()

    def verify(self, key: bytes, nonce: int) -> bool:
        expected = self.hmac_value
        self.compute(key, nonce)
        result = self.hmac_value == expected
        self.hmac_value = expected
        return result

    def serialize(self) -> bytes:
        return struct.pack("!III", self.path_id, self.seq_number, self.node_id) + self.hmac_value


@dataclass
class Challenge:
    path_id: int
    window_start: int
    window_end: int
    challenge_nonce: int

    def serialize(self) -> bytes:
        return struct.pack("!IIII", self.path_id, self.window_start,
                           self.window_end, self.challenge_nonce)


@dataclass
class SketchSnapshot:
    path_id: int
    window_start: int
    window_end: int
    sketch_data: bytes = b""

    def serialize(self) -> bytes:
        return struct.pack("!III", self.path_id, self.window_start,
                           self.window_end) + self.sketch_data
