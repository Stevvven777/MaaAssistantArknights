#!/usr/bin/env python3
"""Build an auditable manifest for BlackFlow live-run diagnostic datasets.

The tool is intentionally read-only with respect to its input runs.  It scans
``debug/BlackFlow/BF-*`` packages and ``callbacks.jsonl``, hashes captured map
images, and writes a machine-readable manifest plus a compact Markdown report
to a separate output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import zlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
EVENT_TYPES = {"BlackFlowRoutingDecision", "BlackFlowPlanProposed"}
CALLBACK_ERROR_NAMES = {"InternalError", "InitFailed", "TaskChainError", "SubTaskError"}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def natural_key(value: str) -> list[Any]:
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", value)]


def integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def parse_timestamp(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def timestamp_from_stat(path: Path) -> tuple[str | None, float | None]:
    try:
        seconds = path.stat().st_mtime
    except OSError:
        return None, None
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat(), seconds


def relative_file(path: Path, run_dir: Path) -> str:
    try:
        return path.relative_to(run_dir).as_posix()
    except ValueError:
        return str(path)


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not path.is_file():
        return None, "missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return None, f"{type(error).__name__}: {error}"
    if not isinstance(payload, dict):
        return None, f"expected object, got {type(payload).__name__}"
    return payload, None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def paeth_predictor(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    distance_left = abs(estimate - left)
    distance_above = abs(estimate - above)
    distance_upper_left = abs(estimate - upper_left)
    if distance_left <= distance_above and distance_left <= distance_upper_left:
        return left
    if distance_above <= distance_upper_left:
        return above
    return upper_left


def png_dhash(path: Path) -> str:
    """Return a 64-bit difference hash for a common non-interlaced 8-bit PNG.

    MaaCore diagnostic screenshots use this representation.  Unsupported PNG
    encodings are reported in the manifest rather than failing the entire run.
    """

    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("not a PNG file")

    offset = len(PNG_SIGNATURE)
    width = height = bit_depth = color_type = interlace = None
    compressed: list[bytes] = []
    palette: list[tuple[int, int, int]] | None = None

    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        chunk_type = data[offset : offset + 4]
        offset += 4
        end = offset + length
        if end + 4 > len(data):
            raise ValueError("truncated PNG chunk")
        chunk = data[offset:end]
        offset = end + 4  # Skip the CRC after retaining deterministic parsing.

        if chunk_type == b"IHDR":
            if len(chunk) != 13:
                raise ValueError("invalid IHDR length")
            (
                width,
                height,
                bit_depth,
                color_type,
                compression_method,
                filter_method,
                interlace,
            ) = struct.unpack(">IIBBBBB", chunk)
            if compression_method != 0 or filter_method != 0:
                raise ValueError("unsupported PNG compression or filter method")
        elif chunk_type == b"PLTE":
            if len(chunk) % 3:
                raise ValueError("invalid PLTE length")
            palette = [tuple(chunk[index : index + 3]) for index in range(0, len(chunk), 3)]
        elif chunk_type == b"IDAT":
            compressed.append(chunk)
        elif chunk_type == b"IEND":
            break

    if None in {width, height, bit_depth, color_type, interlace}:
        raise ValueError("missing IHDR")
    assert width is not None and height is not None
    assert bit_depth is not None and color_type is not None and interlace is not None
    if width <= 0 or height <= 0:
        raise ValueError("invalid PNG dimensions")
    if bit_depth != 8:
        raise ValueError(f"unsupported PNG bit depth {bit_depth}")
    if interlace != 0:
        raise ValueError("interlaced PNG is unsupported")

    channels_by_type = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
    channels = channels_by_type.get(color_type)
    if channels is None:
        raise ValueError(f"unsupported PNG color type {color_type}")
    if color_type == 3 and not palette:
        raise ValueError("indexed PNG has no palette")

    try:
        decoded = zlib.decompress(b"".join(compressed))
    except zlib.error as error:
        raise ValueError(f"invalid PNG IDAT stream: {error}") from error
    row_bytes = width * channels
    expected_size = height * (row_bytes + 1)
    if len(decoded) < expected_size:
        raise ValueError("truncated PNG pixel data")

    sample_x = [round(index * (width - 1) / 8) for index in range(9)]
    sample_y = [round(index * (height - 1) / 7) for index in range(8)]
    requested_rows: dict[int, list[int]] = defaultdict(list)
    for output_row, source_row in enumerate(sample_y):
        requested_rows[source_row].append(output_row)
    samples = [[0] * 9 for _ in range(8)]

    previous = bytearray(row_bytes)
    cursor = 0
    for row_index in range(height):
        filter_type = decoded[cursor]
        cursor += 1
        encoded_row = decoded[cursor : cursor + row_bytes]
        cursor += row_bytes
        row = bytearray(row_bytes)
        for byte_index, encoded_value in enumerate(encoded_row):
            left = row[byte_index - channels] if byte_index >= channels else 0
            above = previous[byte_index]
            upper_left = previous[byte_index - channels] if byte_index >= channels else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = above
            elif filter_type == 3:
                predictor = (left + above) // 2
            elif filter_type == 4:
                predictor = paeth_predictor(left, above, upper_left)
            else:
                raise ValueError(f"unsupported PNG row filter {filter_type}")
            row[byte_index] = (encoded_value + predictor) & 0xFF

        for output_row in requested_rows.get(row_index, []):
            for output_column, source_column in enumerate(sample_x):
                pixel_offset = source_column * channels
                if color_type in {0, 4}:
                    luminance = row[pixel_offset]
                elif color_type in {2, 6}:
                    red, green, blue = row[pixel_offset : pixel_offset + 3]
                    luminance = (299 * red + 587 * green + 114 * blue + 500) // 1000
                else:
                    assert palette is not None
                    palette_index = row[pixel_offset]
                    if palette_index >= len(palette):
                        raise ValueError("PNG palette index out of range")
                    red, green, blue = palette[palette_index]
                    luminance = (299 * red + 587 * green + 114 * blue + 500) // 1000
                samples[output_row][output_column] = luminance
        previous = row

    value = 0
    for row in samples:
        for column in range(8):
            value = (value << 1) | int(row[column] > row[column + 1])
    return f"{value:016x}"


def dhash_distance(first: str, second: str) -> int:
    return (int(first, 16) ^ int(second, 16)).bit_count()


def artifact_record(
    run_id: str,
    run_dir: Path,
    artifact_dir: Path,
    warnings: list[str],
) -> dict[str, Any]:
    snapshot_path = artifact_dir / "snapshot.json"
    captured_path = artifact_dir / "captured.png"
    overlay_path = artifact_dir / "overlay.png"
    payload, snapshot_error = load_json(snapshot_path)
    snapshot = payload or {}

    nodes = snapshot.get("nodes")
    edges = snapshot.get("edges")
    nodes_available = isinstance(nodes, list)
    edges_available = isinstance(edges, list)
    node_count = integer(snapshot.get("node_count"))
    if node_count is None and nodes_available:
        node_count = len(nodes)
    edge_count = integer(snapshot.get("edge_count"))
    if edge_count is None and edges_available:
        edge_count = len(edges)
    if edge_count is None:
        edge_count = integer(snapshot.get("confirmed_edge_count"))

    artifact_name = artifact_dir.name
    key = f"{run_id}/{artifact_name}"
    modified_at, modified_epoch = timestamp_from_stat(
        snapshot_path if snapshot_path.exists() else artifact_dir
    )
    record: dict[str, Any] = {
        "observation_key": key,
        "run_id": run_id,
        "artifact": relative_file(artifact_dir, run_dir),
        "artifact_name": artifact_name,
        "snapshot_file": relative_file(snapshot_path, run_dir) if snapshot_path.exists() else None,
        "snapshot_status": "ok" if snapshot_error is None else snapshot_error,
        "snapshot_modified_at": modified_at,
        "floor": integer(snapshot.get("floor"))
        if integer(snapshot.get("floor")) is not None
        else integer(snapshot.get("recognition_floor")),
        "node_count": node_count,
        "edge_count": edge_count,
        "nodes_available": nodes_available,
        "edges_available": edges_available,
        "current_node": integer(snapshot.get("current_node")),
        "trigger": snapshot.get("trigger") if isinstance(snapshot.get("trigger"), str) else None,
        "observation_id": str(
            snapshot.get("accepted_observation_id") or snapshot.get("observation_id") or ""
        )
        or None,
        "run_revision": integer(snapshot.get("run_revision")),
        "map_revision": integer(snapshot.get("map_revision")),
        "captured_file": relative_file(captured_path, run_dir) if captured_path.is_file() else None,
        "overlay_file": relative_file(overlay_path, run_dir) if overlay_path.is_file() else None,
        "captured_sha256": None,
        "captured_dhash": None,
        "dhash_error": None,
        "exact_duplicate_of": None,
        "exact_group_size": None,
        "perceptual_group_id": None,
        "perceptual_duplicate_of": None,
        "perceptual_group_size": None,
        "events": [],
        "_modified_epoch": modified_epoch,
    }

    if snapshot_error:
        warnings.append(f"{key}: snapshot.json {snapshot_error}")
    if payload is not None and not nodes_available:
        warnings.append(f"{key}: snapshot has no nodes array")
    if payload is not None and not edges_available:
        warnings.append(f"{key}: snapshot has no edges array")

    if captured_path.is_file():
        try:
            record["captured_sha256"] = sha256_file(captured_path)
        except OSError as error:
            warnings.append(f"{key}: captured.png SHA256 failed: {error}")
        try:
            record["captured_dhash"] = png_dhash(captured_path)
        except (OSError, ValueError, struct.error) as error:
            record["dhash_error"] = str(error)
            warnings.append(f"{key}: captured.png dHash failed: {error}")
    else:
        warnings.append(f"{key}: captured.png missing")
    return record


def read_callbacks(
    run_id: str,
    run_dir: Path,
    warnings: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    callback_path = run_dir / "callbacks.jsonl"
    summary: dict[str, Any] = {
        "file_status": "ok",
        "callback_count": 0,
        "strategy_results": [],
        "strategy_failures": [],
        "errors": [],
    }
    if not callback_path.is_file():
        warnings.append(f"{run_id}: callbacks.jsonl missing")
        summary["file_status"] = "missing"
        return [], summary

    events: list[dict[str, Any]] = []
    try:
        stream = callback_path.open("r", encoding="utf-8")
    except OSError as error:
        warnings.append(f"{run_id}: callbacks.jsonl could not be opened: {error}")
        summary["file_status"] = f"{type(error).__name__}: {error}"
        return [], summary

    with stream:
        for line_number, line in enumerate(stream, 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                warnings.append(f"{run_id}: callbacks.jsonl:{line_number}: {error}")
                continue
            if not isinstance(entry, dict):
                continue
            summary["callback_count"] += 1
            timestamp = entry.get("timestamp") if isinstance(entry.get("timestamp"), str) else None
            message_name = entry.get("message_name")
            if isinstance(message_name, str) and (
                message_name in CALLBACK_ERROR_NAMES or message_name.endswith("Error")
            ):
                summary["errors"].append(
                    {
                        "source_line": line_number,
                        "timestamp": timestamp,
                        "message": entry.get("message"),
                        "message_name": message_name,
                    }
                )
            envelope = entry.get("details")
            if not isinstance(envelope, dict):
                continue
            event_type = envelope.get("what")
            details = envelope.get("details")
            if not isinstance(details, dict):
                details = {}
            if event_type == "BlackFlowStrategyResult":
                strategy_result = {
                    "source_line": line_number,
                    "timestamp": timestamp,
                    **details,
                }
                summary["strategy_results"].append(strategy_result)
                if details.get("succeeded") is False:
                    summary["strategy_failures"].append(strategy_result)
            if event_type not in EVENT_TYPES:
                continue
            selected = details.get("selected")
            if not isinstance(selected, dict):
                selected = {}
            move_details = selected if event_type == "BlackFlowPlanProposed" and selected else details
            events.append(
                {
                    "event_id": f"{run_id}:callback:{line_number}",
                    "run_id": run_id,
                    "type": event_type,
                    "timestamp": timestamp,
                    "source_file": relative_file(callback_path, run_dir),
                    "source_line": line_number,
                    "observation_id": str(details.get("observation_id") or "") or None,
                    "floor": integer(details.get("floor")),
                    "run_revision": integer(details.get("run_revision")),
                    "map_revision": integer(details.get("map_revision")),
                    "decision_id": details.get("decision_id"),
                    "transaction_id": details.get("transaction_id"),
                    "proposal_id": details.get("proposal_id"),
                    "selected": selected or None,
                    "target": integer(move_details.get("target")),
                    "landing": integer(move_details.get("landing")),
                    "node_type": move_details.get("node_type"),
                    "node_name": move_details.get("node_name"),
                    "movement": move_details.get("movement"),
                    "reason_category": details.get("reason_category"),
                    "reason_detail": details.get("reason_detail") or details.get("reason"),
                    "associated_observation": None,
                    "association_method": None,
                    "association_delta_seconds": None,
                    "details": details,
                    "_timestamp_epoch": parse_timestamp(timestamp),
                }
            )
    return events, summary


def choose_by_time(event: dict[str, Any], candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    event_time = event.get("_timestamp_epoch")
    timed = [candidate for candidate in candidates if candidate.get("_modified_epoch") is not None]
    if event_time is None or not timed:
        return candidates[-1] if candidates else None
    return min(timed, key=lambda item: abs(item["_modified_epoch"] - event_time))


def associate_events(
    observations: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> None:
    by_run: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        by_run[observation["run_id"]].append(observation)

    for event in events:
        candidates = by_run.get(event["run_id"], [])
        if not candidates:
            event["association_method"] = "unmatched"
            continue

        floor = event.get("floor")
        floor_candidates = [item for item in candidates if item.get("floor") == floor]
        if floor_candidates:
            candidates = floor_candidates

        method = "nearest_timestamp"
        observation_id = event.get("observation_id")
        exact_id = [item for item in candidates if item.get("observation_id") == observation_id]
        if observation_id and exact_id:
            candidates = exact_id
            method = "observation_id"
        else:
            run_revision = event.get("run_revision")
            map_revision = event.get("map_revision")
            exact_revision = [
                item
                for item in candidates
                if item.get("run_revision") == run_revision
                and item.get("map_revision") == map_revision
            ]
            if run_revision is not None and map_revision is not None and exact_revision:
                candidates = exact_revision
                method = "run_and_map_revision"

        selected = choose_by_time(event, candidates)
        if selected is None:
            event["association_method"] = "unmatched"
            continue
        event["associated_observation"] = selected["observation_key"]
        event["association_method"] = method
        event_time = event.get("_timestamp_epoch")
        modified_time = selected.get("_modified_epoch")
        if event_time is not None and modified_time is not None:
            event["association_delta_seconds"] = round(abs(event_time - modified_time), 6)
        selected["events"].append(event["event_id"])


def add_exact_groups(observations: list[dict[str, Any]]) -> None:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        digest = observation.get("captured_sha256")
        if digest:
            groups[digest].append(observation)
    for group in groups.values():
        canonical = group[0]["observation_key"]
        for index, observation in enumerate(group):
            observation["exact_group_size"] = len(group)
            if index:
                observation["exact_duplicate_of"] = canonical


def add_perceptual_groups(observations: list[dict[str, Any]], threshold: int) -> int:
    images = [item for item in observations if item.get("captured_dhash")]
    parent = list(range(len(images)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(first: int, second: int) -> None:
        first_root = find(first)
        second_root = find(second)
        if first_root != second_root:
            parent[second_root] = first_root

    for first in range(len(images)):
        for second in range(first + 1, len(images)):
            if dhash_distance(images[first]["captured_dhash"], images[second]["captured_dhash"]) <= threshold:
                union(first, second)

    groups: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, image in enumerate(images):
        groups[find(index)].append(image)
    ordered_groups = sorted(groups.values(), key=lambda group: group[0]["observation_key"])
    for group_number, group in enumerate(ordered_groups, 1):
        group_id = f"dhash-{group_number:04d}"
        canonical = group[0]["observation_key"]
        for index, observation in enumerate(group):
            observation["perceptual_group_id"] = group_id
            observation["perceptual_group_size"] = len(group)
            if index:
                observation["perceptual_duplicate_of"] = canonical
    return len(ordered_groups)


def as_object_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def callback_error_names(errors: Iterable[dict[str, Any]]) -> list[str]:
    names = {
        item.get("message_name")
        for item in errors
        if isinstance(item.get("message_name"), str) and item.get("message_name")
    }
    return sorted(names)


def effective_run_outcome(
    prior_manifest: dict[str, Any] | None,
    callback_summary: dict[str, Any],
) -> tuple[str, str, str]:
    """Return status, effective stop reason, and the evidence source.

    Callback failures take precedence over legacy manifests because older live
    runners could write ``task_completed`` after MaaCore had already emitted an
    unsuccessful strategy result or task-chain error.
    """

    manifest_strategy_failures = as_object_list(
        prior_manifest.get("strategy_failures") if prior_manifest else None
    )
    strategy_failures = [
        *callback_summary.get("strategy_failures", []),
        *manifest_strategy_failures,
    ]
    if strategy_failures:
        failure = strategy_failures[-1]
        outcome = failure.get("outcome") if isinstance(failure.get("outcome"), str) else "unknown"
        return "failed", f"strategy_failed:{outcome}", "callback_or_manifest_strategy_result"

    manifest_errors = as_object_list(prior_manifest.get("errors") if prior_manifest else None)
    errors = [*callback_summary.get("errors", []), *manifest_errors]
    if errors:
        names = callback_error_names(errors)
        suffix = ",".join(names) if names else "unknown"
        return "failed", f"callback_error:{suffix}", "callback_or_manifest_error"

    if prior_manifest is None:
        return "incomplete", "unknown", "manifest_missing_or_unreadable"

    manifest_status = prior_manifest.get("status")
    manifest_stop_reason = prior_manifest.get("stop_reason")
    if manifest_status == "failed" or (
        isinstance(manifest_stop_reason, str)
        and (manifest_stop_reason.startswith("strategy_failed:") or manifest_stop_reason == "startup_failure")
    ):
        return "failed", str(manifest_stop_reason or "unknown"), "manifest"
    if not isinstance(manifest_stop_reason, str) or not manifest_stop_reason:
        return "unknown", "unknown", "manifest_without_stop_reason"
    if manifest_status in {"incomplete", "unknown"} or manifest_stop_reason in {
        "keyboard_interrupt",
        "max_runtime",
    } or manifest_stop_reason.startswith("identical_map_observation_limit_"):
        return "incomplete", manifest_stop_reason, "manifest"
    return "completed", manifest_stop_reason, "manifest"


def run_metadata(
    run_id: str,
    run_dir: Path,
    observations: list[dict[str, Any]],
    callback_summary: dict[str, Any],
) -> dict[str, Any]:
    config, config_error = load_json(run_dir / "run_config.json")
    prior_manifest, manifest_error = load_json(run_dir / "manifest.json")
    status, stop_reason, status_source = effective_run_outcome(prior_manifest, callback_summary)
    floors = Counter(
        str(item["floor"]) if item.get("floor") is not None else "unknown"
        for item in observations
        if item["run_id"] == run_id
    )
    sorted_floors = sorted(
        floors.items(),
        key=lambda item: (
            item[0] == "unknown",
            integer(item[0]) if integer(item[0]) is not None else 0,
            item[0],
        ),
    )
    return {
        "run_id": run_id,
        "path": str(run_dir),
        "diagnostic_package_count": sum(item["run_id"] == run_id for item in observations),
        "floor_package_counts": dict(sorted_floors),
        "run_config_file": "run_config.json" if config is not None else None,
        "run_config_status": "ok" if config_error is None else config_error,
        "repo_head": config.get("repo_head") if config else None,
        "started_at": (config or prior_manifest or {}).get("started_at"),
        "task": config.get("task") if config else None,
        "prior_manifest_file": "manifest.json" if prior_manifest is not None else None,
        "prior_manifest_status": "ok" if manifest_error is None else manifest_error,
        "finished_at": prior_manifest.get("finished_at") if prior_manifest else None,
        "status": status,
        "status_source": status_source,
        "stop_reason": stop_reason,
        "manifest_stop_reason": prior_manifest.get("stop_reason") if prior_manifest else None,
        "callback_file_status": callback_summary.get("file_status"),
        "callback_count": (
            prior_manifest.get("callback_count")
            if prior_manifest and prior_manifest.get("callback_count") is not None
            else callback_summary.get("callback_count")
        ),
        "observed_callback_count": callback_summary.get("callback_count"),
        "strategy_result_count": len(callback_summary.get("strategy_results", [])),
        "strategy_failure_count": len(callback_summary.get("strategy_failures", [])),
        "callback_error_count": len(callback_summary.get("errors", [])),
        "callback_error_names": callback_error_names(callback_summary.get("errors", [])),
        "reported_errors": prior_manifest.get("errors") if prior_manifest else None,
    }


def strip_internal_fields(items: Iterable[dict[str, Any]]) -> None:
    for item in items:
        for key in [key for key in item if key.startswith("_")]:
            del item[key]


def markdown_value(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def markdown_report(manifest: dict[str, Any]) -> str:
    summary = manifest["summary"]
    observations = manifest["observations"]
    events = manifest["routing_events"]
    lines = [
        "# BlackFlow dataset summary",
        "",
        f"Generated: `{manifest['generated_at']}`",
        "",
        "## Totals",
        "",
        "| Runs | Packages | Readable snapshots | Captured images | Exact unique images | dHash groups | Route events | Warnings |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        "| {run_count} | {package_count} | {readable_snapshot_count} | {captured_image_count} | "
        "{exact_unique_image_count} | {perceptual_group_count} | {routing_event_count} | {warning_count} |".format(
            **summary
        ),
        "",
        "The dHash grouping threshold is "
        f"`{manifest['dhash_hamming_threshold']}` Hamming bits. SHA256 is authoritative for exact duplicates.",
        "",
        "## Runs",
        "",
        "| Run | Status | Packages | Floors | Strategy | Stop reason | Source |",
        "| --- | --- | ---: | --- | --- | --- | --- |",
    ]
    for run in manifest["runs"]:
        floor_text = ", ".join(
            f"{floor}: {count}" for floor, count in run["floor_package_counts"].items()
        ) or "—"
        task = run.get("task") or {}
        lines.append(
            "| {run} | {status} | {count} | {floors} | {strategy} | {stop} | `{source}` |".format(
                run=markdown_value(run["run_id"]),
                status=markdown_value(run.get("status")),
                count=run["diagnostic_package_count"],
                floors=markdown_value(floor_text),
                strategy=markdown_value(task.get("blackflow_strategy")),
                stop=markdown_value(run.get("stop_reason")),
                source=markdown_value(run["path"]),
            )
        )

    lines.extend(
        [
            "",
            "## Diagnostic packages",
            "",
            "| Observation | Floor | Nodes | Edges | Current | Trigger | Revisions | SHA256 | dHash | Events |",
            "| --- | ---: | ---: | ---: | --- | --- | --- | --- | --- | ---: |",
        ]
    )
    for observation in observations:
        revision = f"r{observation.get('run_revision')}/m{observation.get('map_revision')}"
        digest = observation.get("captured_sha256")
        exact_mark = " (dup)" if observation.get("exact_duplicate_of") else ""
        lines.append(
            "| {key} | {floor} | {nodes} | {edges} | {current} | {trigger} | {revision} | "
            "`{sha}`{exact_mark} | `{dhash}` | {event_count} |".format(
                key=markdown_value(observation["observation_key"]),
                floor=markdown_value(observation.get("floor")),
                nodes=markdown_value(observation.get("node_count")),
                edges=markdown_value(observation.get("edge_count")),
                current=markdown_value(observation.get("current_node")),
                trigger=markdown_value(observation.get("trigger")),
                revision=markdown_value(revision),
                sha=digest[:12] if digest else "—",
                exact_mark=exact_mark,
                dhash=observation.get("captured_dhash") or "—",
                event_count=len(observation.get("events", [])),
            )
        )

    lines.extend(
        [
            "",
            "## Routing events",
            "",
            "| Event | Type | Floor | Target | Movement | Reason | Associated snapshot | Method |",
            "| --- | --- | ---: | --- | --- | --- | --- | --- |",
        ]
    )
    if events:
        for event in events:
            target = event.get("target") or event.get("landing")
            reason = event.get("reason_category") or event.get("reason_detail")
            lines.append(
                "| {event} | {type} | {floor} | {target} | {movement} | {reason} | {snapshot} | {method} |".format(
                    event=markdown_value(event["event_id"]),
                    type=markdown_value(event["type"]),
                    floor=markdown_value(event.get("floor")),
                    target=markdown_value(target),
                    movement=markdown_value(event.get("movement")),
                    reason=markdown_value(reason),
                    snapshot=markdown_value(event.get("associated_observation")),
                    method=markdown_value(event.get("association_method")),
                )
            )
    else:
        lines.append("| — | — | — | — | — | — | — | — |")

    warnings = manifest["warnings"]
    lines.extend(["", "## Warnings", ""])
    if not warnings:
        lines.append("None.")
    else:
        for warning in warnings[:100]:
            lines.append(f"- {warning}")
        if len(warnings) > 100:
            lines.append(f"- … {len(warnings) - 100} additional warnings are in the JSON manifest.")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "runs",
        nargs="+",
        type=Path,
        help="One or more BlackFlow live-run directories (the parents of debug/BlackFlow).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "debug" / "blackflow_dataset_index",
        help="Directory for dataset_manifest.json and dataset_summary.md.",
    )
    parser.add_argument(
        "--dhash-threshold",
        type=int,
        default=4,
        help="Maximum 64-bit dHash Hamming distance for a perceptual group (default: 4).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not 0 <= args.dhash_threshold <= 64:
        raise ValueError("--dhash-threshold must be in [0, 64]")

    resolved_runs: list[tuple[str, Path]] = []
    used_ids: Counter[str] = Counter()
    for supplied_path in args.runs:
        run_dir = supplied_path.resolve()
        if not run_dir.is_dir():
            raise FileNotFoundError(f"run directory does not exist: {run_dir}")
        used_ids[run_dir.name] += 1
        suffix = f"#{used_ids[run_dir.name]}" if used_ids[run_dir.name] > 1 else ""
        resolved_runs.append((f"{run_dir.name}{suffix}", run_dir))

    warnings: list[str] = []
    observations: list[dict[str, Any]] = []
    routing_events: list[dict[str, Any]] = []
    callback_summaries: dict[str, dict[str, Any]] = {}
    for run_id, run_dir in resolved_runs:
        diagnostic_root = run_dir / "debug" / "BlackFlow"
        if not diagnostic_root.is_dir():
            warnings.append(f"{run_id}: debug/BlackFlow directory missing")
        else:
            artifact_dirs = sorted(
                (path for path in diagnostic_root.glob("BF-*") if path.is_dir()),
                key=lambda path: natural_key(path.name),
            )
            if not artifact_dirs:
                warnings.append(f"{run_id}: no BF-* diagnostic packages found")
            for artifact_dir in artifact_dirs:
                observations.append(artifact_record(run_id, run_dir, artifact_dir, warnings))
        events, callback_summary = read_callbacks(run_id, run_dir, warnings)
        routing_events.extend(events)
        callback_summaries[run_id] = callback_summary

    add_exact_groups(observations)
    perceptual_group_count = add_perceptual_groups(observations, args.dhash_threshold)
    associate_events(observations, routing_events)

    runs = [
        run_metadata(run_id, run_dir, observations, callback_summaries[run_id])
        for run_id, run_dir in resolved_runs
    ]
    image_observations = [item for item in observations if item.get("captured_sha256")]
    exact_digests = {item["captured_sha256"] for item in image_observations}
    summary = {
        "run_count": len(runs),
        "package_count": len(observations),
        "readable_snapshot_count": sum(item["snapshot_status"] == "ok" for item in observations),
        "captured_image_count": len(image_observations),
        "exact_unique_image_count": len(exact_digests),
        "exact_duplicate_image_count": len(image_observations) - len(exact_digests),
        "perceptual_group_count": perceptual_group_count,
        "routing_event_count": len(routing_events),
        "routing_event_types": dict(sorted(Counter(item["type"] for item in routing_events).items())),
        "associated_routing_event_count": sum(
            item.get("associated_observation") is not None for item in routing_events
        ),
        "run_status_counts": dict(sorted(Counter(item["status"] for item in runs).items())),
        "failed_run_count": sum(item["status"] == "failed" for item in runs),
        "incomplete_run_count": sum(item["status"] == "incomplete" for item in runs),
        "warning_count": len(warnings),
    }

    strip_internal_fields(observations)
    strip_internal_fields(routing_events)
    manifest = {
        "schema": "maa.blackflow.dataset-manifest.v1",
        "generated_at": utc_now(),
        "generator": relative_file(Path(__file__).resolve(), REPO_ROOT),
        "dhash_hamming_threshold": args.dhash_threshold,
        "summary": summary,
        "runs": runs,
        "observations": observations,
        "routing_events": routing_events,
        "warnings": warnings,
    }

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "dataset_manifest.json"
    markdown_path = output_dir / "dataset_summary.md"
    json_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(markdown_report(manifest), encoding="utf-8")

    print(
        json.dumps(
            {
                "json": str(json_path),
                "markdown": str(markdown_path),
                "summary": summary,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2) from error
