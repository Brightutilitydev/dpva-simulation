#!/usr/bin/env python3
import hashlib
import struct
import time
import sys
import os
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from src.simulation.network import SimulationNetwork, NetworkNode, DataPacket
from src.dpvl.core import VerificationEngine, TrustedKeyStore, AnomalyResponseEngine
from src.protocol.messages import (
    Probe, Challenge, SketchSnapshot, AnomalyType,
)


def _keypair_from_id(node_id: int) -> tuple[bytes, bytes]:
    seed = struct.pack("!I", node_id) * 8
    key = hashlib.sha256(seed + b"key").digest()
    return key, key


def setup_topology() -> tuple[SimulationNetwork, TrustedKeyStore]:
    net = SimulationNetwork()
    keystore = TrustedKeyStore()
    names = {1: "Source", 2: "Router-A", 3: "Router-B", 4: "Router-C", 5: "Destination"}
    for nid in range(1, 6):
        sk, pk = _keypair_from_id(nid)
        node = NetworkNode(nid, names[nid], sk, pk)
        net.add_node(node)
        keystore.register(nid, pk)
    net.add_link(1, 2)
    net.add_link(2, 3)
    net.add_link(3, 4)
    net.add_link(4, 5)
    net.add_link(2, 5)
    return net, keystore


def run_scenario(
    name: str,
    description: str,
    malicious_nodes: Optional[list[int]] = None,
    override_path: Optional[list[int]] = None,
    inject_packets: Optional[list[dict]] = None,
) -> dict:
    net, keystore = setup_topology()
    malicious_nodes = malicious_nodes or []
    for nid in malicious_nodes:
        net.nodes[nid].opvm.is_malicious = True
        net.nodes[nid].is_malicious = True

    src_sk, _ = _keypair_from_id(1)
    dst_sk, _ = _keypair_from_id(5)
    ve_src = VerificationEngine(1, src_sk, keystore)
    ve_dst = VerificationEngine(5, dst_sk, keystore)
    are = AnomalyResponseEngine()
    are.set_policy(AnomalyType.TAG_CHAIN_MISMATCH, "quarantine")
    are.set_policy(AnomalyType.SKETCH_DEVIATION, "alert")

    path = net.get_path(1, 5)
    claim = ve_src.create_claim(path)
    ve_dst.claim_store.store(claim)

    ppv_passed = None
    ppv_detail = ""
    ocpv_passed = None
    ocpv_detail = ""
    pfa_passed = None
    pfa_detail = ""
    alerts = []
    hop_trace = []

    probe = Probe(
        path_id=claim.path_id,
        nonce=hashlib.sha256(name.encode()).digest()[0],
        hop_count=1,
        accumulated_tag=b"\x00" * 32,
    )
    trace = net.route_packet(1, 5, probe, malicious_override=override_path)
    hop_trace = [
        {"node_id": t["node_id"], "node_name": t["node_name"],
         "is_malicious": t["is_malicious"]}
        for t in trace
    ]

    result = ve_dst.verify_probe(probe, path)
    ppv_passed = result.success
    ppv_detail = result.details
    action = are.handle(result, {"scenario": name})
    alerts.append({
        "source": "PPV",
        "success": result.success,
        "anomaly": result.anomaly_type,
        "detail": result.details,
        "action": action,
    })

    ve_src.record_packet(claim.path_id, 1)
    for seq in range(2, 22):
        pkt = DataPacket(path_id=claim.path_id, seq=seq, has_token=(seq % 3 == 0))
        net.route_packet(1, 5, pkt, malicious_override=override_path)
        ve_src.record_packet(claim.path_id, seq)
        ve_dst.record_packet(claim.path_id, seq)

    if inject_packets:
        for ip in inject_packets:
            inj_pkt = DataPacket(path_id=claim.path_id, seq=ip["seq"], has_token=True)
            net.route_packet(ip.get("src", 1), ip.get("dst", 5), inj_pkt)
            if ip.get("record_at_dst", True):
                ve_dst.record_packet(claim.path_id, ip["seq"])

    window_end = 1010 if inject_packets else 100
    challenge = ve_dst.create_challenge(claim.path_id, 1, window_end)
    src_snapshot = ve_src.sketch.export()
    snap = SketchSnapshot(claim.path_id, 1, window_end, src_snapshot)
    sketch_result = ve_dst.verify_sketch(challenge, snap)
    ocpv_passed = sketch_result.success
    ocpv_detail = sketch_result.details
    action2 = are.handle(sketch_result, {"scenario": name + "_opcv"})
    alerts.append({
        "source": "OPCV",
        "success": sketch_result.success,
        "anomaly": sketch_result.anomaly_type,
        "detail": sketch_result.details,
        "action": action2,
    })

    return {
        "name": name,
        "description": description,
        "path": path,
        "path_names": [net.nodes[n].name for n in path],
        "malicious_nodes": malicious_nodes,
        "hop_trace": hop_trace,
        "ppv": {"passed": ppv_passed, "detail": ppv_detail},
        "opcv": {"passed": ocpv_passed, "detail": ocpv_detail},
        "alerts": alerts,
    }


def run_all_scenarios() -> dict:
    scenarios = [
        run_scenario(
            name="Normal Operation",
            description="All nodes behave honestly. No attacks.",
        ),
        run_scenario(
            name="BGP Hijack",
            description="Router-C (Node 4) is malicious and produces invalid tags.",
            malicious_nodes=[4],
        ),
        run_scenario(
            name="Man-in-the-Middle",
            description="Router-A (Node 2) diverts traffic through a shortcut, skipping Router-B and Router-C.",
            malicious_nodes=[2],
            override_path=[1, 2, 5],
        ),
        run_scenario(
            name="Packet Injection",
            description="Router-B (Node 3) injects packets with sequence numbers not seen by the source.",
            inject_packets=[
                {"seq": 999, "src": 3, "dst": 5, "record_at_dst": True},
                {"seq": 1000, "src": 3, "dst": 5, "record_at_dst": True, "record_at_src": False},
            ],
        ),
        run_scenario(
            name="Packet Drop",
            description="Router-C (Node 4) drops packets by producing invalid tags (caught by PPV).",
            malicious_nodes=[4],
        ),
    ]
    return {"scenarios": scenarios, "timestamp": time.time()}


def main():
    print()
    print("  DYNAMIC PATH VERIFICATION ALGORITHM (DPVA)")
    print("  Simulation Results")
    print()
    data = run_all_scenarios()
    for s in data["scenarios"]:
        status = "PASS" if s["ppv"]["passed"] and s["opcv"]["passed"] else "DETECTED"
        print(f"  [{status}] {s['name']}")
        print(f"         {s['description']}")
        print(f"         Path: {' → '.join(s['path_names'])}")
        print(f"         PPV:  {'OK' if s['ppv']['passed'] else 'BLOCKED'} — {s['ppv']['detail']}")
        print(f"         OPCV: {'OK' if s['opcv']['passed'] else 'ALERT'} — {s['opcv']['detail']}")
        print()


if __name__ == "__main__":
    main()
