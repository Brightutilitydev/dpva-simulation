import hashlib
import hmac as hmac_mod
import struct
from typing import Optional


def hash_node_id(public_key: bytes) -> int:
    return int.from_bytes(hashlib.sha256(public_key).digest()[:4], "big")


def compute_hmac(key: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def compute_tag(key: bytes, nonce: int, prev_tag: bytes) -> bytes:
    msg = struct.pack("!I", nonce) + prev_tag
    return compute_hmac(key, msg)


def verify_tag(key: bytes, nonce: int, prev_tag: bytes, received_tag: bytes) -> bool:
    expected = compute_tag(key, nonce, prev_tag)
    return hmac_mod.compare_digest(expected, received_tag)


class CountMinSketch:
    def __init__(self, width: int = 1024, depth: int = 4):
        self.width = width
        self.depth = depth
        self.counters = [[0] * width for _ in range(depth)]
        self._hash_seeds = list(range(1, depth + 1))

    def _hash(self, seed: int, item: bytes) -> int:
        h = hashlib.sha256(struct.pack("!I", seed) + item).digest()
        return int.from_bytes(h[:4], "big") % self.width

    def add(self, item: bytes, count: int = 1):
        for d in range(self.depth):
            idx = self._hash(self._hash_seeds[d], item)
            self.counters[d][idx] += count

    def estimate(self, item: bytes) -> int:
        vals = []
        for d in range(self.depth):
            idx = self._hash(self._hash_seeds[d], item)
            vals.append(self.counters[d][idx])
        return min(vals)

    def merge(self, other: "CountMinSketch"):
        for d in range(self.depth):
            for i in range(self.width):
                self.counters[d][i] += other.counters[d][i]

    def export(self) -> bytes:
        import io
        buf = io.BytesIO()
        for d in range(self.depth):
            for c in self.counters[d]:
                buf.write(struct.pack("!I", c))
        return buf.getvalue()

    @classmethod
    def import_(cls, data: bytes, width: int = 1024, depth: int = 4) -> "CountMinSketch":
        cms = cls(width, depth)
        off = 0
        for d in range(depth):
            for i in range(width):
                cms.counters[d][i] = struct.unpack_from("!I", data, off)[0]
                off += 4
        return cms

    def clone(self) -> "CountMinSketch":
        c = CountMinSketch(self.width, self.depth)
        import copy
        c.counters = copy.deepcopy(self.counters)
        return c


class CuckooFilter:
    def __init__(self, capacity: int = 4096, bucket_size: int = 4, fingerprint_bits: int = 64):
        self.capacity = capacity
        self.bucket_size = bucket_size
        self.fingerprint_bits = fingerprint_bits
        self.buckets = [[] for _ in range(capacity)]
        self.max_kicks = 500

    def _fingerprint(self, item: bytes) -> int:
        h = hashlib.sha256(item).digest()
        mask = (1 << self.fingerprint_bits) - 1
        return int.from_bytes(h[:8], "big") & mask

    def _index(self, fp: int) -> int:
        return fp % self.capacity

    def _alt_index(self, idx: int, fp: int) -> int:
        return (idx ^ (hashlib.sha256(struct.pack("!Q", fp)).digest()[0] % self.capacity)) % self.capacity

    def insert(self, item: bytes) -> bool:
        fp = self._fingerprint(item)
        i1 = self._index(fp)
        i2 = self._alt_index(i1, fp)

        for idx in (i1, i2):
            if len(self.buckets[idx]) < self.bucket_size:
                self.buckets[idx].append(fp)
                return True

        idx = i1 if (hashlib.sha256(item).digest()[0] & 1) == 0 else i2
        for _ in range(self.max_kicks):
            kicked = self.buckets[idx][0]
            self.buckets[idx][0] = fp
            fp = kicked
            idx = self._alt_index(idx, fp)
            if len(self.buckets[idx]) < self.bucket_size:
                self.buckets[idx].append(fp)
                return True
        return False

    def contains(self, item: bytes) -> bool:
        fp = self._fingerprint(item)
        i1 = self._index(fp)
        i2 = self._alt_index(i1, fp)
        return fp in self.buckets[i1] or fp in self.buckets[i2]

    def export(self) -> bytes:
        buf = struct.pack("!II", self.capacity, self.bucket_size)
        for bucket in self.buckets:
            buf += struct.pack("!B", len(bucket))
            for fp in bucket:
                buf += struct.pack("!Q", fp)
        return buf

    @classmethod
    def import_(cls, data: bytes) -> "CuckooFilter":
        off = 0
        capacity = struct.unpack_from("!I", data, off)[0]
        off += 4
        bucket_size = struct.unpack_from("!I", data, off)[0]
        off += 4
        cf = cls(capacity, bucket_size)
        for i in range(capacity):
            b_len = struct.unpack_from("!B", data, off)[0]
            off += 1
            bucket = []
            for _ in range(b_len):
                fp = struct.unpack_from("!Q", data, off)[0]
                bucket.append(fp)
                off += 8
            cf.buckets[i] = bucket
        return cf
