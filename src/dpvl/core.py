from __future__ import annotations
import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Callable

from src.utils.crypto import compute_tag, verify_tag, CountMinSketch, CuckooFilter
from src.protocol.messages import (
    PathClaim, Probe, ProbeAck, Challenge, SketchSnapshot,
    MessageType, AnomalyType,
)


@dataclass
class VerificationResult:
    success: bool
    anomaly_type: int = 0
    details: str = ""


class PathClaimStore:
    def __init__(self):
        self._claims: dict[int, PathClaim] = {}

    def store(self, claim: PathClaim):
        self._claims[claim.path_id] = claim

    def get(self, path_id: int) -> Optional[PathClaim]:
        return self._claims.get(path_id)

    def remove_expired(self, now: int):
        to_remove = [
            pid for pid, c in self._claims.items()
            if c.timestamp + c.ttl < now
        ]
        for pid in to_remove:
            del self._claims[pid]


class TrustedKeyStore:
    def __init__(self):
        self._keys: dict[int, bytes] = {}

    def register(self, node_id: int, public_key: bytes):
        self._keys[node_id] = public_key

    def get(self, node_id: int) -> Optional[bytes]:
        return self._keys.get(node_id)


class VerificationEngine:
    def __init__(self, node_id: int, private_key: bytes, keystore: TrustedKeyStore):
        self.node_id = node_id
        self.private_key = private_key
        self.keystore = keystore
        self.claim_store = PathClaimStore()
        self.sketch = CountMinSketch()
        self.on_anomaly: Optional[Callable[[AnomalyType, dict], None]] = None
        self._challenge_history: set[int] = set()

    def create_claim(self, path: list[int], ttl: int = 300) -> PathClaim:
        path_id = int.from_bytes(
            hashlib.sha256(struct.pack("!I", self.node_id) +
                          b"".join(struct.pack("!I", n) for n in path) +
                          struct.pack("!I", int(time.time()))).digest()[:4],
            "big"
        )
        claim = PathClaim(
            path_id=path_id,
            claimant_id=self.node_id,
            timestamp=int(time.time()),
            ttl=ttl,
            hop_count=len(path),
            nonce=int.from_bytes(hashlib.sha256(struct.pack("!I", int(time.time()))).digest()[:1], "big"),
            path=path,
        )
        self.claim_store.store(claim)
        return claim

    def verify_probe(self, probe: Probe, expected_path: list[int]) -> VerificationResult:
        claim = self.claim_store.get(probe.path_id)
        if not claim:
            return VerificationResult(False, AnomalyType.PATH_CLAIM_EXPIRED, "No claim found")

        if claim.timestamp + claim.ttl < int(time.time()):
            return VerificationResult(False, AnomalyType.PATH_CLAIM_EXPIRED, "Claim expired")

        expected_tag = b"\x00" * 32
        for node_id in claim.path:
            key = self.keystore.get(node_id)
            if not key:
                return VerificationResult(False, AnomalyType.TAG_CHAIN_MISMATCH,
                                          f"Unknown key for node {node_id}")
            expected_tag = compute_tag(key, probe.nonce, expected_tag)

        received_tag = probe.accumulated_tag
        if len(received_tag) != 32:
            return VerificationResult(False, AnomalyType.TAG_CHAIN_MISMATCH, "Invalid tag length")

        import hmac as hmac_mod
        if hmac_mod.compare_digest(expected_tag, received_tag):
            return VerificationResult(True)
        return VerificationResult(False, AnomalyType.TAG_CHAIN_MISMATCH, "Tag chain mismatch")

    def create_challenge(self, path_id: int, window_start: int, window_end: int) -> Challenge:
        nonce = int.from_bytes(hashlib.sha256(struct.pack("!II", path_id, int(time.time()))).digest()[:4], "big")
        self._challenge_history.add(nonce)
        return Challenge(path_id, window_start, window_end, nonce)

    def verify_sketch(self, challenge: Challenge, snapshot: SketchSnapshot) -> VerificationResult:
        if challenge.challenge_nonce not in self._challenge_history:
            return VerificationResult(False, AnomalyType.REPLAY_DETECTED, "Unknown challenge nonce")
        self._challenge_history.discard(challenge.challenge_nonce)

        src_sketch = CountMinSketch.import_(snapshot.sketch_data)
        dst_seqs = getattr(self, '_packet_log', {}).get(challenge.path_id, set())
        dst_seqs = {s for s in dst_seqs if challenge.window_start <= s <= challenge.window_end}

        missing = 0
        for seq in dst_seqs:
            est = src_sketch.estimate(struct.pack("!II", challenge.path_id, seq))
            if est == 0:
                missing += 1

        if missing > 0:
            return VerificationResult(False, AnomalyType.SKETCH_DEVIATION,
                                      f"Missing {missing} packets in source sketch (injection)")

        return VerificationResult(True)

    def record_packet(self, path_id: int, seq: int):
        self.sketch.add(struct.pack("!II", path_id, seq))
        if not hasattr(self, '_packet_log'):
            self._packet_log = {}
        if path_id not in self._packet_log:
            self._packet_log[path_id] = set()
        self._packet_log[path_id].add(seq)


class AnomalyResponseEngine:
    def __init__(self):
        self.policy: dict[int, str] = {}
        self.alert_history: list[dict] = []

    def set_policy(self, anomaly_type: int, action: str):
        self.policy[anomaly_type] = action

    def handle(self, result: VerificationResult, context: dict) -> str:
        if result.success:
            return "allow"

        action = self.policy.get(result.anomaly_type, "alert")
        self.alert_history.append({
            "anomaly_type": result.anomaly_type,
            "details": result.details,
            "action": action,
            "context": context,
            "timestamp": int(time.time()),
        })
        return action

    def get_alerts(self) -> list[dict]:
        return self.alert_history
