from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
import threading
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from pydantic import BaseModel


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _json_default(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "value"):
        return value.value
    return str(value)


def _safe_git_revision(project_root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=project_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip() or None


class RunLogger:
    """Durable, append-only experiment logging created before any live API request."""

    def __init__(
        self,
        *,
        project_root: Path,
        output_root: Path,
        config_snapshot: dict[str, Any],
        run_label: str,
        fsync_jsonl: bool = True,
    ) -> None:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        suffix = uuid.uuid4().hex[:8]
        self.run_id = f"{timestamp}_{run_label}_{suffix}"
        self.run_dir = output_root / self.run_id
        self.task_dir = self.run_dir / "tasks"
        self.agentdojo_raw_dir = self.run_dir / "agentdojo_raw"
        self.task_dir.mkdir(parents=True, exist_ok=False)
        self.agentdojo_raw_dir.mkdir(parents=True, exist_ok=False)
        self.project_root = project_root
        self.fsync_jsonl = fsync_jsonl
        self._lock = threading.Lock()
        self._task_context: ContextVar[dict[str, Any]] = ContextVar("scopeguard_task_context", default={})
        self._executed_calls: ContextVar[list[dict[str, Any]]] = ContextVar("scopeguard_executed_calls", default=[])

        snapshot = {
            "run_id": self.run_id,
            "created_at": utc_now(),
            "status": "initialized",
            "config": config_snapshot,
            "environment": {
                "python": sys.version,
                "platform": platform.platform(),
                "agentdojo_version": self._package_version("agentdojo"),
                "scopeguard_version": self._package_version("scopeguard-k"),
                "git_revision": _safe_git_revision(project_root),
                "openrouter_api_key_present": bool(os.getenv("OPENROUTER_API_KEY")),
            },
            "secret_logging_policy": "Environment variable values are never persisted.",
        }
        self.write_json("config_snapshot.json", snapshot)
        self.write_json("run_status.json", {"run_id": self.run_id, "status": "initialized", "updated_at": utc_now()})

    @staticmethod
    def _package_version(package: str) -> str | None:
        try:
            return importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return None

    def write_json(self, relative_path: str | Path, payload: Any) -> None:
        path = self.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, default=_json_default)
        path.write_text(serialized + "\n", encoding="utf-8")

    def append_jsonl(self, relative_path: str | Path, payload: dict[str, Any]) -> None:
        path = self.run_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "record_id": uuid.uuid4().hex,
            "timestamp": utc_now(),
            **self._task_context.get(),
            **payload,
        }
        line = json.dumps(record, sort_keys=True, ensure_ascii=False, default=_json_default) + "\n"
        with self._lock, path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            if self.fsync_jsonl:
                os.fsync(handle.fileno())

    def set_status(self, status: str, **details: Any) -> None:
        self.write_json(
            "run_status.json",
            {"run_id": self.run_id, "status": status, "updated_at": utc_now(), **details},
        )

    @contextmanager
    def task_context(self, **context: Any) -> Iterator[None]:
        context = {"run_id": self.run_id, **context}
        token = self._task_context.set(context)
        calls_token = self._executed_calls.set([])
        self.append_jsonl("task_events.jsonl", {"event": "task_started"})
        try:
            yield
        except Exception as exc:
            self.append_jsonl(
                "errors.jsonl",
                {"event": "task_exception", "exception_type": type(exc).__name__, "message": str(exc)},
            )
            raise
        finally:
            self.append_jsonl("task_events.jsonl", {"event": "task_finished"})
            self._executed_calls.reset(calls_token)
            self._task_context.reset(token)

    @property
    def current_task(self) -> dict[str, Any]:
        return dict(self._task_context.get())

    @property
    def executed_calls(self) -> list[dict[str, Any]]:
        return list(self._executed_calls.get())

    def record_executed_call(self, payload: dict[str, Any]) -> None:
        calls = list(self._executed_calls.get())
        calls.append(payload)
        self._executed_calls.set(calls)

    def record_trajectory(self, event: str, payload: Any) -> None:
        self.append_jsonl("trajectory.jsonl", {"event": event, "payload": payload})

    def record_llm_call(self, payload: dict[str, Any]) -> None:
        self.append_jsonl("llm_calls.jsonl", payload)

    def record_usage(self, payload: dict[str, Any]) -> None:
        self.append_jsonl("llm_usage.jsonl", payload)

    def record_tool_call(self, payload: dict[str, Any]) -> None:
        self.append_jsonl("tool_calls.jsonl", payload)

    def record_policy_decision(self, payload: dict[str, Any]) -> None:
        self.append_jsonl("policy_decisions.jsonl", payload)

    def record_reviewer_decision(self, payload: dict[str, Any]) -> None:
        self.append_jsonl("reviewer_decisions.jsonl", payload)

    def record_task_result(self, payload: dict[str, Any]) -> None:
        self.append_jsonl("task_results.jsonl", payload)
        key_material = "|".join(
            str(payload.get(key, ""))
            for key in ("policy", "budget", "user_task_id", "injection_task_id", "attack")
        )
        digest = hashlib.sha256(key_material.encode("utf-8")).hexdigest()[:16]
        self.write_json(self.task_dir.relative_to(self.run_dir) / f"{digest}.json", payload)

