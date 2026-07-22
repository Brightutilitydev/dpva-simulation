#!/usr/bin/env python3
import json
import os
import sys
import threading
import webbrowser
import traceback
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web.logger import log, log_scenario_view, log_action
from src.simulation.engine import (
    run_simulation, bulk_simulate, TOPOLOGY_TEMPLATES, AttackProfile,
)
from src.simulation.run import run_all_scenarios


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        try:
            if path == "/api/simulate":
                data = run_all_scenarios()
                log("GET", path, 200, f"{len(data['scenarios'])} scenarios")
                self._json(200, data)

            elif path == "/api/run":
                template = params.get("topology", ["simple"])[0]
                attacks_json = params.get("attacks", ["[]"])[0]
                n_packets = int(params.get("packets", ["50"])[0])
                sample_rate = float(params.get("sample", ["0.1"])[0])

                attacks = json.loads(attacks_json) if attacks_json != "[]" else []
                attack_profiles = []
                for a in attacks:
                    attack_profiles.append(AttackProfile(
                        name=a.get("name", "custom"),
                        description=a.get("description", ""),
                        malicious_node_ids=a.get("malicious_ids", []),
                        override_path=a.get("override_path"),
                        inject_packets=a.get("inject_packets", []),
                        drop_seqs=a.get("drop_seqs", []),
                        phase=a.get("phase", 3),
                    ))

                log_action("RUN_SIM", f"topology={template} packets={n_packets} attacks={len(attack_profiles)}")
                result = run_simulation(
                    topology_template=template,
                    packet_count=n_packets,
                    sample_rate=sample_rate,
                    attacks=attack_profiles,
                )
                log("GET", path, 200, f"result: ppv={result.ppv['passed']} opcv={result.opcv['passed']}")

                resp = {
                    "scenario_name": result.scenario_name,
                    "path": result.path,
                    "path_names": result.path_names,
                    "malicious_nodes": result.malicious_nodes,
                    "hop_trace": result.hop_trace,
                    "ppv": result.ppv,
                    "opcv": result.opcv,
                    "pfa": result.pfa,
                    "metrics": {
                        "ppv_detected": result.metrics.ppv_detected,
                        "opcv_detected": result.metrics.opcv_detected,
                        "pfa_detected": result.metrics.pfa_detected,
                        "detection_latency_ms": round(result.metrics.detection_latency_ms, 2),
                        "verification_overhead_us": round(result.metrics.verification_overhead_us, 2),
                        "probe_time_ms": round(result.metrics.probe_time_ms, 3),
                        "packets_sent": result.metrics.packets_sent,
                        "packets_received": result.metrics.packets_received,
                        "packets_injected": result.metrics.packets_injected,
                        "packets_dropped": result.metrics.packets_dropped,
                        "tag_chain_valid": result.metrics.tag_chain_valid,
                        "sketch_deviation": round(result.metrics.sketch_deviation, 4),
                        "alerts_triggered": result.metrics.alerts_triggered,
                    },
                    "alerts": result.alerts,
                    "timing": result.timing,
                }
                self._json(200, resp)

            elif path == "/api/bulk":
                template = params.get("topology", ["simple"])[0]
                log_action("BULK_SIM", f"topology={template}")
                results = bulk_simulate(template=template)
                self._json(200, {"results": results, "count": len(results)})

            elif path == "/api/topologies":
                tpl = {k: {
                    "nodes": v["nodes"],
                    "links": len(v["links"]),
                    "names": v["names"],
                } for k, v in TOPOLOGY_TEMPLATES.items()}
                self._json(200, tpl)

            elif path == "/api/log":
                self._json(200, {"status": "ok"})

            elif path == "/api/view":
                scenario = params.get("scenario", [""])[0]
                log_scenario_view(scenario)
                self._json(200, {"status": "logged"})

            elif path == "/" or path == "/index.html":
                self.path = "/static/index.html"
                super().do_GET()
            else:
                super().do_GET()

        except Exception as e:
            tb = traceback.format_exc()
            log("ERROR", path, 500, str(e))
            log_action("STACKTRACE", tb)
            self._json(500, {"error": str(e), "trace": tb})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            if path == "/api/view":
                data = json.loads(body)
                log_scenario_view(data.get("scenario", "unknown"))
                self._json(200, {"status": "logged"})
            elif path == "/api/action":
                data = json.loads(body)
                log_action(data.get("action", "?"), data.get("params", ""))
                self._json(200, {"status": "logged"})
            else:
                self._json(404, {"error": "unknown endpoint"})
        except Exception as e:
            self._json(500, {"error": str(e)})

    def _json(self, status: int, data: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, *a):
        pass


def main():
    port = int(os.environ.get("PORT", 8080))
    os.chdir(Path(__file__).parent)
    server = HTTPServer(("0.0.0.0", port), Handler)

    url = f"http://localhost:{port}"
    log("SERVER", "START", 0, f"listening on {url}")

    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("SERVER", "STOP", 0, "shutdown")
        server.server_close()


if __name__ == "__main__":
    main()
