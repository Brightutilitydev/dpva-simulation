from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Optional

from src.simulation.opvm import OnPathVerificationModule
from src.protocol.messages import Probe, Challenge, SketchSnapshot


@dataclass
class DataPacket:
    path_id: int
    seq: int
    has_token: bool = False


class NetworkNode:
    def __init__(self, node_id: int, name: str, secret_key: bytes, public_key: bytes,
                 is_malicious: bool = False):
        self.node_id = node_id
        self.name = name
        self.secret_key = secret_key
        self.public_key = public_key
        self.opvm = OnPathVerificationModule(node_id, secret_key, is_malicious)
        self.is_malicious = is_malicious

    def __repr__(self):
        return f"{self.name}(ID={self.node_id})"


class SimulationNetwork:
    def __init__(self):
        self.nodes: dict[int, NetworkNode] = {}
        self.topology: dict[int, list[int]] = {}
        self._packet_log: list[dict] = []

    def add_node(self, node: NetworkNode):
        self.nodes[node.node_id] = node
        if node.node_id not in self.topology:
            self.topology[node.node_id] = []

    def add_link(self, n1_id: int, n2_id: int):
        if n1_id in self.topology and n2_id in self.topology:
            self.topology[n1_id].append(n2_id)
            self.topology[n2_id].append(n1_id)

    def get_path(self, src_id: int, dst_id: int) -> Optional[list[int]]:
        visited = set()
        path = []

        def dfs(current: int, target: int) -> bool:
            if current == target:
                return True
            visited.add(current)
            for neighbor in self.topology.get(current, []):
                if neighbor not in visited:
                    if dfs(neighbor, target):
                        path.insert(0, neighbor)
                        return True
            return False

        if dfs(src_id, dst_id):
            return [src_id] + path
        return None

    def route_packet(self, src_id: int, dst_id: int, payload: object,
                     malicious_override: Optional[list[int]] = None) -> list[dict]:
        path = malicious_override or self.get_path(src_id, dst_id)
        if not path:
            raise ValueError(f"No path from {src_id} to {dst_id}")

        trace = []
        for i in range(len(path)):
            current = path[i]
            node = self.nodes[current]

            if isinstance(payload, Probe):
                new_probe = node.opvm.process_probe(payload)
                payload.accumulated_tag = new_probe.accumulated_tag
                payload.hop_count = new_probe.hop_count
            elif hasattr(payload, "path_id"):
                pkt = payload
                if hasattr(pkt, "seq"):
                    node.opvm.process_data_packet(pkt.path_id, pkt.seq,
                                                  has_token=getattr(pkt, "has_token", False))

            next_hop = path[i + 1] if i < len(path) - 1 else None
            self._packet_log.append({
                "time": time.time(),
                "from": current,
                "to": next_hop,
                "payload_type": type(payload).__name__,
                "node_name": node.name,
                "is_malicious": node.is_malicious,
            })
            trace.append({
                "node_id": current,
                "node_name": node.name,
                "is_malicious": node.is_malicious,
                "payload_type": type(payload).__name__,
            })

        return trace
