#!/usr/bin/env python3
"""
ReDAN 实验评估驱动（安全版）
- 不进行端口扫描/洪泛
- 不构造可用于现实攻击的伪造报文
- 仅在你自己的 docker NAT 环境里：
  1) 触发 client/server 的 DoS 测试流程
  2) 用 NAT 侧 conntrack 作为 ground truth 判断是否“映射被异常关闭”
  3) 统计成功率、保存证据用于报告
"""

import json
import os
import subprocess
import time
from dataclasses import dataclass, asdict
from typing import List, Optional


@dataclass
class FlowKey:
    client_ip: str
    server_ip: str
    dport: int  # server port, e.g. 5003


@dataclass
class TrialResult:
    trial_id: int
    start_ts: float
    end_ts: float
    before_conntrack: str
    after_conntrack: str
    flow_state_before: Optional[str]
    flow_state_after: Optional[str]
    dos_observed: bool
    notes: str


class ConntrackEvaluator:
    def __init__(self, nat_container: str, flow: FlowKey, out_dir: str = "./output/eval"):
        self.nat_container = nat_container
        self.flow = flow
        self.out_dir = out_dir
        os.makedirs(self.out_dir, exist_ok=True)

    def _docker_exec(self, cmd: str) -> str:
        """Run a command inside nat_container and return stdout."""
        full = ["docker", "exec", "-i", self.nat_container, "sh", "-lc", cmd]
        p = subprocess.run(full, capture_output=True, text=True)
        if p.returncode != 0:
            raise RuntimeError(f"docker exec failed: {cmd}\nSTDERR:\n{p.stderr}")
        return p.stdout

    def snapshot_conntrack(self) -> str:
        return self._docker_exec("conntrack -L || true")

    def extract_flow_state(self, conntrack_text: str) -> Optional[str]:
        """
        Try to find the TCP state for the flow:
        src=<client_ip> dst=<server_ip> dport=<dport>
        Return state token like ESTABLISHED/CLOSE/... or None if not found.
        """
        needle_1 = f"src={self.flow.client_ip} dst={self.flow.server_ip}"
        needle_2 = f"dport={self.flow.dport}"
        for line in conntrack_text.splitlines():
            if needle_1 in line and needle_2 in line:
                # Example: "tcp 6 9 CLOSE src=... dst=... sport=... dport=5003 ..."
                parts = line.split()
                # Find the first ALLCAPS-ish state token
                for tok in parts:
                    if tok.isupper() and tok in {
                        "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT",
                        "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE"
                    }:
                        return tok
        return None

    def save_text(self, name: str, content: str) -> str:
        path = os.path.join(self.out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path


class ExperimentDriver:
    """
    只负责“触发你现有的 client/server 测试流程”并等待结束。
    你可以根据你的仓库把命令改成实际入口。
    """
    def __init__(self, client_container: str, server_container: str):
        self.client_container = client_container
        self.server_container = server_container

    def _run(self, container: str, cmd: str, timeout: int = 60) -> str:
        full = ["docker", "exec", "-i", container, "sh", "-lc", cmd]
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError(f"{container} cmd failed: {cmd}\nSTDERR:\n{p.stderr}")
        return p.stdout

    def ensure_server_running(self) -> None:
        # 你可以换成更可靠的方式：supervisor / systemd / pidfile
        # 这里简单检查 python3 server.py 是否在跑
        out = self._run(self.server_container, "ps aux | grep -v grep | grep -E 'python3 /scripts/.*server.py' || true")
        if not out.strip():
            # 后台启动 server.py
            self._run(self.server_container, "nohup python3 /scripts/server.py >/logs/server_run.log 2>&1 &", timeout=10)

    def trigger_client_dos_flow(self) -> str:
        """
        触发 client 发起 5001/5003 的连接流程（由你现有 client.py 实现）。
        如果你的 client.py 需要参数，在这里加上。
        """
        return self._run(self.client_container, "python3 /scripts/client.py", timeout=120)


def main():
    # 根据你的 compose 配置修改容器名
    NAT_CONTAINER = "nat_container"
    CLIENT_CONTAINER = "client_container"
    SERVER_CONTAINER = "server_container"

    # 你的实验地址（按你当前环境）
    FLOW = FlowKey(client_ip="192.168.1.100", server_ip="10.0.0.10", dport=5003)

    OUT_DIR = "./output/eval"
    TRIALS = 20
    SLEEP_BETWEEN = 2.0

    evaluator = ConntrackEvaluator(NAT_CONTAINER, FLOW, out_dir=OUT_DIR)
    driver = ExperimentDriver(CLIENT_CONTAINER, SERVER_CONTAINER)

    driver.ensure_server_running()

    results: List[TrialResult] = []
    success = 0

    for i in range(1, TRIALS + 1):
        start = time.time()
        before = evaluator.snapshot_conntrack()
        state_before = evaluator.extract_flow_state(before)

        # 触发一次你现有的 client/server DoS 测试流程
        notes = ""
        try:
            client_out = driver.trigger_client_dos_flow()
            notes = f"client_out_len={len(client_out)}"
        except Exception as e:
            notes = f"client_trigger_error={e}"

        # 给 NAT/conntrack 一点时间完成状态迁移
        time.sleep(1.5)

        after = evaluator.snapshot_conntrack()
        state_after = evaluator.extract_flow_state(after)

        # 判据：同一条 flow 从 ESTABLISHED 变成 CLOSE（或直接消失）
        dos_observed = (state_before == "ESTABLISHED" and (state_after == "CLOSE" or state_after is None))
        if dos_observed:
            success += 1

        end = time.time()

        # 保存证据
        evaluator.save_text(f"trial_{i:03d}_before.txt", before)
        evaluator.save_text(f"trial_{i:03d}_after.txt", after)

        results.append(TrialResult(
            trial_id=i,
            start_ts=start,
            end_ts=end,
            before_conntrack=f"trial_{i:03d}_before.txt",
            after_conntrack=f"trial_{i:03d}_after.txt",
            flow_state_before=state_before,
            flow_state_after=state_after,
            dos_observed=dos_observed,
            notes=notes
        ))

        print(f"[trial {i:03d}] before={state_before} after={state_after} dos_observed={dos_observed}")
        time.sleep(SLEEP_BETWEEN)

    summary = {
        "trials": TRIALS,
        "success": success,
        "success_rate": (success / TRIALS) if TRIALS else 0.0,
        "flow": asdict(FLOW),
        "results": [asdict(r) for r in results],
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[+] Done. success={success}/{TRIALS} rate={summary['success_rate']:.3f}")
    print(f"[+] Evidence written under {OUT_DIR}/ (summary.json + per-trial conntrack snapshots)")


if __name__ == "__main__":
    main()
