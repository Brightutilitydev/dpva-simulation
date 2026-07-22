from __future__ import annotations
import struct
from typing import Optional

from src.utils.crypto import CountMinSketch, CuckooFilter, compute_tag
from src.protocol.messages import Probe, AnomalyType


class OnPathVerificationModule:
    def __init__(self, node_id: int, secret_key: bytes, is_malicious: bool = False):
        self.node_id = node_id
        self.secret_key = secret_key
        self.is_malicious = is_malicious
        self.sketch = CountMinSketch()
        self.audit_log = CuckooFilter(capacity=2048)
        self._tag_cache: dict[int, bytes] = {}

    def process_probe(self, probe: Probe) -> Probe:
        prev_tag = probe.accumulated_tag if probe.accumulated_tag else b"\x00" * 32
        if self.is_malicious:
            tag = compute_tag(b"evil_key", probe.nonce, prev_tag)
        else:
            tag = compute_tag(self.secret_key, probe.nonce, prev_tag)

        return Probe(
            path_id=probe.path_id,
            nonce=probe.nonce,
            hop_count=probe.hop_count + 1,
            accumulated_tag=tag,
        )

    def process_data_packet(self, path_id: int, seq: int, has_token: bool = False):
        item = struct.pack("!II", path_id, seq)
        if has_token or seq % 10 == 0:
            self.sketch.add(item)
            self.audit_log.insert(item)

    def export_sketch(self) -> bytes:
        return self.sketch.export()

    def export_audit_log(self) -> bytes:
        return self.audit_log.export()
