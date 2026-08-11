#!/usr/bin/env python3
"""Run the BlackFlow roguelike task against a real device and collect diagnostics.

The runner deliberately uses MaaCore's public Python FFI instead of duplicating
the game's navigation.  With ``blackflow_diagnostics=full`` every accepted map
observation can produce ``captured.png``, ``overlay.png`` and ``snapshot.json``
under the selected user directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src" / "Python"))

from asst.asst import Asst  # noqa: E402
from asst.utils import Message  # noqa: E402


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def repository_state() -> tuple[str, bool | None]:
    """Return the checked-out commit and whether the worktree has changes."""

    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=normal"],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
        )
        return head, dirty
    except (OSError, subprocess.SubprocessError):
        return "unknown", None


@dataclass
class ObservationSummary:
    artifact: str
    floor: int
    observation_id: str
    trigger: str
    has_images: bool
    semantic_fingerprint: str


class CallbackRecorder:
    def __init__(self, output_path: Path, planner_case_dir: Path) -> None:
        self.output_path = output_path
        self.planner_case_dir = planner_case_dir
        self.lock = threading.Lock()
        self.count = 0
        self.planner_case_count = 0
        self.errors: list[dict[str, Any]] = []
        self.strategy_results: list[dict[str, Any]] = []
        self.strategy_failures: list[dict[str, Any]] = []

    def record(self, message: int, details: bytes | None) -> None:
        try:
            decoded = details.decode("utf-8") if details else "{}"
            payload = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {"raw": repr(details)}

        try:
            message_name = Message(message).name
        except ValueError:
            message_name = f"Unknown({message})"

        entry = {
            "timestamp": utc_now(),
            "message": message,
            "message_name": message_name,
            "details": payload,
        }
        with self.lock:
            with self.output_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.count += 1
            if isinstance(payload, dict) and payload.get("what") == "BlackFlowPlanProposed":
                event_details = payload.get("details")
                if isinstance(event_details, dict):
                    planner_case = event_details.get("planner_case")
                    proposal_id = event_details.get("proposal_id")
                    if isinstance(planner_case, dict) and isinstance(proposal_id, str) and proposal_id:
                        self.planner_case_dir.mkdir(parents=True, exist_ok=True)
                        case_path = self.planner_case_dir / f"{proposal_id}.json"
                        case_path.write_text(
                            json.dumps(planner_case, ensure_ascii=False, indent=2),
                            encoding="utf-8",
                        )
                        expected_path = self.planner_case_dir / f"{proposal_id}.expected.json"
                        expected_path.write_text(
                            json.dumps(
                                {
                                    "schema_version": 1,
                                    "proposal_id": proposal_id,
                                    "selected": event_details.get("selected"),
                                    "selected_page_intent": event_details.get("selected_page_intent", ""),
                                    "planned_route": event_details.get("planned_route", []),
                                    "planned_route_steps": event_details.get("planned_route_steps", []),
                                    "confirmed_safety": event_details.get("confirmed_safety"),
                                    "relaxed_safety": event_details.get("relaxed_safety"),
                                    "reason": event_details.get("reason", ""),
                                    "reason_category": event_details.get("reason_category", ""),
                                    "rejection_counts": event_details.get("rejection_counts", {}),
                                    "runners_up": event_details.get("runners_up", []),
                                },
                                ensure_ascii=False,
                                indent=2,
                            ),
                            encoding="utf-8",
                        )
                        self.planner_case_count += 1
            if isinstance(payload, dict) and payload.get("what") == "BlackFlowStrategyResult":
                strategy_result = payload.get("details")
                if isinstance(strategy_result, dict):
                    self.strategy_results.append(strategy_result)
                    if not strategy_result.get("succeeded", False):
                        self.strategy_failures.append(strategy_result)
            if message in {
                Message.InternalError.value,
                Message.InitFailed.value,
                Message.TaskChainError.value,
                Message.SubTaskError.value,
            }:
                self.errors.append(entry)


def _artifact_sort_key(path: Path) -> tuple[int, int, str]:
    match = re.fullmatch(r"BF-A(\d+)-(\d+)", path.parent.name)
    if match is None:
        return (sys.maxsize, sys.maxsize, path.parent.name)
    return (int(match.group(1)), int(match.group(2)), path.parent.name)


def _semantic_fingerprint(payload: dict[str, Any]) -> str:
    nodes = payload.get("nodes")
    edges = payload.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return ""
    canonical_nodes = sorted(
        (
            {
                key: node.get(key)
                for key in (
                    "id",
                    "row",
                    "column",
                    "type",
                    "name",
                    "identity_revealed",
                    "identity_state",
                    "progress",
                )
            }
            for node in nodes
            if isinstance(node, dict)
        ),
        key=lambda node: (node.get("id") is None, node.get("id")),
    )
    canonical_edges = sorted(
        (
            {
                key: edge.get(key)
                for key in ("first", "second", "knowledge", "forced_by_connectivity_constraint")
            }
            for edge in edges
            if isinstance(edge, dict)
        ),
        key=lambda edge: (
            edge.get("first") is None,
            edge.get("first"),
            edge.get("second") is None,
            edge.get("second"),
        ),
    )
    semantic = {
        "floor": payload.get("recognition_floor"),
        "current_node": payload.get("current_node"),
        "nodes": canonical_nodes,
        "edges": canonical_edges,
    }
    encoded = json.dumps(semantic, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def discover_observations(user_dir: Path) -> list[ObservationSummary]:
    root = user_dir / "debug" / "BlackFlow"
    observations: list[ObservationSummary] = []
    if not root.exists():
        return observations

    for snapshot_path in sorted(root.glob("*/snapshot.json"), key=_artifact_sort_key):
        try:
            payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        artifact_dir = snapshot_path.parent
        observations.append(
            ObservationSummary(
                artifact=str(artifact_dir.relative_to(user_dir)),
                floor=int(payload.get("recognition_floor", 0) or 0),
                observation_id=str(payload.get("accepted_observation_id", "")),
                trigger=str(payload.get("trigger", "")),
                has_images=(artifact_dir / "captured.png").exists()
                and (artifact_dir / "overlay.png").exists(),
                semantic_fingerprint=_semantic_fingerprint(payload),
            )
        )
    return observations


def identical_observation_tail(observations: list[ObservationSummary]) -> int:
    if not observations or not observations[-1].semantic_fingerprint:
        return 0
    fingerprint = observations[-1].semantic_fingerprint
    count = 0
    for observation in reversed(observations):
        if observation.semantic_fingerprint != fingerprint:
            break
        count += 1
    return count


def parse_args() -> argparse.Namespace:
    default_runtime = REPO_ROOT / "build" / "blackflow" / "bin" / "RelWithDebInfo"
    default_adb = Path(r"G:\MuMuPlayer\nx_device\12.0\shell\adb.exe")
    default_run = REPO_ROOT / "debug" / "blackflow_live" / datetime.now().strftime(
        "%Y%m%d-%H%M%S"
    )

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, default=default_runtime)
    parser.add_argument("--user-dir", type=Path, default=default_run)
    parser.add_argument("--adb", type=Path, default=default_adb)
    parser.add_argument("--address", default="127.0.0.1:16384")
    parser.add_argument("--connection-config", default="MuMuEmulator12")
    parser.add_argument("--strategy", default="burn")
    parser.add_argument("--mode", type=int, default=0)
    parser.add_argument("--difficulty", type=int, default=0)
    parser.add_argument("--squad", default="特勤分队")
    parser.add_argument("--roles", default="稳扎稳打")
    parser.add_argument("--core-char", default="机械师")
    parser.add_argument("--starts-count", type=int, default=1)
    parser.add_argument("--image-limit", type=int, default=100)
    parser.add_argument("--max-runtime", type=float, default=3600.0)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Load MaaCore and resources, then exit before connecting to a device.",
    )
    parser.add_argument(
        "--stop-after-floor",
        type=int,
        default=0,
        help="Stop after this floor has enough persisted image observations; 0 disables.",
    )
    parser.add_argument("--min-images-at-stop-floor", type=int, default=1)
    parser.add_argument(
        "--max-identical-map-observations",
        type=int,
        default=8,
        help="Stop after this many consecutive semantically identical map snapshots; 0 disables.",
    )
    parser.add_argument(
        "--investment-enabled",
        action=argparse.BooleanOptionalAction,
        default=False,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    runtime = args.runtime.resolve()
    user_dir = args.user_dir.resolve()
    adb_path = args.adb.resolve()
    user_dir.mkdir(parents=True, exist_ok=True)

    if not (runtime / "MaaCore.dll").is_file():
        raise FileNotFoundError(f"MaaCore.dll not found under {runtime}")
    if not (runtime / "resource").is_dir():
        raise FileNotFoundError(f"resource directory/link not found under {runtime}")
    if not adb_path.is_file():
        raise FileNotFoundError(f"adb executable not found: {adb_path}")
    if not 0 <= args.image_limit <= 100:
        raise ValueError("--image-limit must be in [0, 100]")
    if args.max_identical_map_observations < 0:
        raise ValueError("--max-identical-map-observations must be non-negative")

    recorder = CallbackRecorder(user_dir / "callbacks.jsonl", user_dir / "planner_cases")

    @Asst.CallBackType
    def callback(message: int, details: bytes, _argument: Any) -> None:
        recorder.record(message, details)

    started_at = utc_now()
    task_params: dict[str, Any] = {
        "theme": "BlackFlow",
        "mode": args.mode,
        "difficulty": args.difficulty,
        "squad": args.squad,
        "roles": args.roles,
        "core_char": args.core_char,
        "starts_count": args.starts_count,
        "investment_enabled": args.investment_enabled,
        "blackflow_strategy": args.strategy,
        "blackflow_diagnostics": "full",
        "blackflow_diagnostic_image_limit": args.image_limit,
    }
    repo_head, working_tree_dirty = repository_state()
    run_config = {
        "started_at": started_at,
        "repo_head": repo_head,
        "working_tree_dirty": working_tree_dirty,
        "runtime": str(runtime),
        "user_dir": str(user_dir),
        "adb": str(adb_path),
        "address": args.address,
        "connection_config": args.connection_config,
        "task": task_params,
        "stop_after_floor": args.stop_after_floor,
        "min_images_at_stop_floor": args.min_images_at_stop_floor,
        "max_runtime": args.max_runtime,
        "max_identical_map_observations": args.max_identical_map_observations,
        "validate_only": args.validate_only,
    }
    (user_dir / "run_config.json").write_text(
        json.dumps(run_config, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    if not Asst.load(path=runtime, user_dir=user_dir):
        raise RuntimeError("MaaCore or resource loading failed")
    if args.validate_only:
        print(json.dumps({"validated": True, **run_config}, ensure_ascii=False, indent=2))
        return 0

    assistant = Asst(callback=callback)
    try:
        if not assistant.connect(str(adb_path), args.address, args.connection_config):
            raise RuntimeError(
                f"MaaCore failed to connect to {args.address} using {args.connection_config}"
            )

        task_id = assistant.append_task("Roguelike", task_params)
        if task_id <= 0:
            raise RuntimeError("MaaCore rejected the Roguelike task")
        if not assistant.start():
            raise RuntimeError("MaaCore failed to start the Roguelike task")

        monotonic_start = time.monotonic()
        stop_reason = "task_completed"
        last_reported_counts: dict[int, int] = {}
        while assistant.running():
            elapsed = time.monotonic() - monotonic_start
            if elapsed >= args.max_runtime:
                stop_reason = "max_runtime"
                assistant.stop()
                break

            observations = discover_observations(user_dir)
            identical_tail = identical_observation_tail(observations)
            floor_image_counts: dict[int, int] = {}
            for observation in observations:
                if observation.has_images:
                    floor_image_counts[observation.floor] = (
                        floor_image_counts.get(observation.floor, 0) + 1
                    )
            if floor_image_counts != last_reported_counts:
                print(
                    json.dumps(
                        {"elapsed": round(elapsed, 1), "floor_images": floor_image_counts},
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
                last_reported_counts = floor_image_counts

            if args.stop_after_floor > 0 and (
                floor_image_counts.get(args.stop_after_floor, 0)
                >= args.min_images_at_stop_floor
            ):
                stop_reason = f"floor_{args.stop_after_floor}_image_target_reached"
                assistant.stop()
                break
            if (
                args.max_identical_map_observations > 0
                and identical_tail >= args.max_identical_map_observations
            ):
                stop_reason = f"identical_map_observation_limit_{identical_tail}"
                assistant.stop()
                break
            time.sleep(args.poll_interval)

    except KeyboardInterrupt:
        stop_reason = "keyboard_interrupt"
        assistant.stop()
    finally:
        observations = discover_observations(user_dir)
        stop_reason = locals().get("stop_reason", "startup_failure")
        if recorder.strategy_failures and stop_reason == "task_completed":
            failure = recorder.strategy_failures[-1]
            stop_reason = f"strategy_failed:{failure.get('outcome', 'unknown')}"
        if recorder.errors and stop_reason == "task_completed":
            error_names = sorted({str(error.get("message_name", "unknown")) for error in recorder.errors})
            stop_reason = f"callback_error:{','.join(error_names)}"
        guard_failure = (
            stop_reason in {"max_runtime", "keyboard_interrupt", "startup_failure"}
            or stop_reason.startswith("identical_map_observation_limit_")
            or stop_reason.startswith("strategy_failed:")
            or stop_reason.startswith("callback_error:")
        )
        succeeded = not recorder.errors and not recorder.strategy_failures and not guard_failure
        manifest = {
            **run_config,
            "finished_at": utc_now(),
            "stop_reason": stop_reason,
            "succeeded": succeeded,
            "callback_count": recorder.count,
            "planner_case_count": recorder.planner_case_count,
            "errors": recorder.errors,
            "strategy_results": recorder.strategy_results,
            "strategy_failures": recorder.strategy_failures,
            "observations": [asdict(item) for item in observations],
        }
        (user_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0 if manifest["succeeded"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
