from src.protocol.messages import Probe, AnomalyType
from src.simulation.network import SimulationNetwork, DataPacket


class AttackScenario:
    def __init__(self, name: str, description: str, expected_anomaly: int):
        self.name = name
        self.description = description
        self.expected_anomaly = expected_anomaly

    def run(self, net: SimulationNetwork, src_id: int, dst_id: int, **kwargs) -> dict:
        raise NotImplementedError


class BGRHijackAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            "BGP Hijack",
            "Malicious node impersonates the destination, attracting traffic via a false path",
            AnomalyType.TAG_CHAIN_MISMATCH,
        )

    def run(self, net, src_id, dst_id, **kwargs) -> dict:
        hijacker_id = kwargs.get("hijacker_id")
        claim_path = net.get_path(src_id, hijacker_id)
        return {
            "attack": self.name,
            "claimed_path": claim_path,
            "expected_anomaly": self.expected_anomaly,
        }


class MITMAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            "Man-in-the-Middle",
            "Malicious node intercepts and forwards traffic through an unexpected path",
            AnomalyType.SKETCH_DEVIATION,
        )

    def run(self, net, src_id, dst_id, **kwargs) -> dict:
        malicious_override = kwargs.get("malicious_path")
        return {
            "attack": self.name,
            "override_path": malicious_override,
            "expected_anomaly": self.expected_anomaly,
        }


class PacketInjectionAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            "Packet Injection",
            "Malicious node injects packets not originating from the source",
            AnomalyType.SKETCH_DEVIATION,
        )

    def run(self, net, src_id, dst_id, **kwargs) -> dict:
        injector_id = kwargs.get("injector_id", src_id)
        count = kwargs.get("count", 5)
        return {
            "attack": self.name,
            "injector_id": injector_id,
            "injected_count": count,
            "expected_anomaly": self.expected_anomaly,
        }


class PacketDropAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            "Packet Drop",
            "Malicious node drops packets without forwarding them",
            AnomalyType.SEQUENCE_GAP,
        )

    def run(self, net, src_id, dst_id, **kwargs) -> dict:
        dropper_id = kwargs.get("dropper_id")
        drop_count = kwargs.get("drop_count", 3)
        return {
            "attack": self.name,
            "dropper_id": dropper_id,
            "drop_count": drop_count,
            "expected_anomaly": self.expected_anomaly,
        }


class ReplayAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            "Replay Attack",
            "Malicious node replays previously captured verification tokens",
            AnomalyType.REPLAY_DETECTED,
        )

    def run(self, net, src_id, dst_id, **kwargs) -> dict:
        return {
            "attack": self.name,
            "expected_anomaly": self.expected_anomaly,
        }
