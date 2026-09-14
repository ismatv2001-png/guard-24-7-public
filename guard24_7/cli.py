#!/usr/bin/env python3
"""guard24_7 CLI: checklist de turno, preflight no-pisarse, watch 24/7, verificación y latido de nube.

Reglas inamovibles que esta herramienta CONSERVA (normas del propietario 13-sep-2026):
  - Un solo coordinador (01a06515-d1d4-7473-aea6-bd02d0c9d925); esto no despacha ni crea politica.
  - Registro unico work-claim-v2: un escritor activo por proyecto/raiz/alcance; preflight es SOLO LECTURA.
  - RAM: techo 7 GiB usados / suelo 1 GiB libre; el rearranque automatico de pestanas queda bloqueado
    por debajo del suelo.
  - Secretos, tokens, OTP y cookies jamas por argv/logs/chat: esta CLI no los maneja ni los imprime.
  - 0 EUR incremental: sin llamadas a proveedor de pago; gh solo con credenciales ya guardadas.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import sqlite3
import sys
import time
import unicodedata
import urllib.request
from pathlib import Path
from typing import Any, Callable

SHA256_HEX = set("0123456789abcdef")
FLOOR_FREE_GIB = 1.0   # suelo de RAM libre
CEIL_USED_GIB = 7.0    # techo de RAM usada
RESTART_COOLDOWN_S = 30 * 60
MAX_RESTARTS_PER_DAY = 6
TARGETS_DEFAULT = ("127.0.0.1", 3081), ("127.0.0.1", 3082)


# ---------------------------------------------------------------- utilidades

def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_text(value: str) -> str:
    # Espejo exacto de work_claims.normalize_text (NFKC, colapso de espacios, casefold).
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def utc_now_text() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def compute_identity_hashes(project_id: str, project_root: str, scope_text: str) -> dict[str, str]:
    # Espejo exacto de work_claims.prepare_claim: hashes de identidad del registro.
    root = os.path.normcase(str(Path(os.path.expandvars(project_root)).expanduser().resolve(strict=True)))
    return {
        "projectRoot": root,
        "projectRootHash": sha256_text(normalize_text(root)),
        "scopeHash": sha256_text(canonical_json({"projectId": project_id, "scope": normalize_text(scope_text)})),
    }


# ---------------------------------------------------------------------- RAM

def read_ram_windows() -> dict[str, float]:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        raise OSError("GlobalMemoryStatusEx failed")
    gib = 1024.0 ** 3
    return {
        "total_gib": stat.ullTotalPhys / gib,
        "free_gib": stat.ullAvailPhys / gib,
        "used_gib": (stat.ullTotalPhys - stat.ullAvailPhys) / gib,
    }


def read_ram_linux() -> dict[str, float]:
    info: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        key, _, rest = line.partition(":")
        if key in ("MemTotal", "MemAvailable"):
            info[key] = int(rest.strip().split()[0]) * 1024
    gib = 1024.0 ** 3
    total = info.get("MemTotal", 0) / gib
    free = info.get("MemAvailable", 0) / gib
    return {"total_gib": total, "free_gib": free, "used_gib": total - free}


def read_ram() -> dict[str, float]:
    return read_ram_windows() if os.name == "nt" else read_ram_linux()


def ram_verdict(ram: dict[str, float]) -> str:
    if ram["free_gib"] < FLOOR_FREE_GIB:
        return "RED"
    if ram["used_gib"] > CEIL_USED_GIB:
        return "WARN"
    return "OK"


# --------------------------------------------------------------- heartbeats

def append_heartbeat(state_dir: Path, record: dict[str, Any]) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    chain_file = state_dir / "heartbeat.jsonl"
    previous = "0" * 64
    if chain_file.exists():
        lines = [l for l in chain_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        if lines:
            previous = json.loads(lines[-1]).get("hash", previous)
    record = dict(record)
    record["prevHash"] = previous
    record["hash"] = sha256_text(previous + "\n" + canonical_json({k: v for k, v in record.items() if k != "hash"}))
    with chain_file.open("a", encoding="utf-8") as stream:
        stream.write(canonical_json(record) + "\n")
    return chain_file


def verify_chain(state_dir: Path) -> dict[str, Any]:
    chain_file = state_dir / "heartbeat.jsonl"
    if not chain_file.exists():
        return {"ok": False, "records": 0, "errors": ["heartbeat.jsonl missing"]}
    errors: list[str] = []
    previous = "0" * 64
    count = 0
    for lineno, line in enumerate(chain_file.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {lineno}: invalid JSON: {exc}")
            break
        count += 1
        if record.get("prevHash") != previous:
            errors.append(f"line {lineno}: prevHash mismatch")
        expected = sha256_text(record["prevHash"] + "\n" + canonical_json({k: v for k, v in record.items() if k != "hash"}))
        if record.get("hash") != expected:
            errors.append(f"line {lineno}: hash mismatch (cadena rota o manipulada)")
        previous = record.get("hash", "0" * 64)
    return {"ok": not errors, "records": count, "errors": errors}


def append_alert(state_dir: Path, condition: str, detail: dict[str, Any]) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    alert_file = state_dir / "alerts.jsonl"
    key = sha256_text(condition)
    if alert_file.exists():
        for line in alert_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                if json.loads(line).get("key") == key:
                    return alert_file  # ya alertado: una sola alerta por condicion
            except json.JSONDecodeError:
                continue
    record = {"key": key, "at": utc_now_text(), "condition": condition, "detail": detail}
    with alert_file.open("a", encoding="utf-8") as stream:
        stream.write(canonical_json(record) + "\n")
    return alert_file


def alert_status(state_dir: Path, condition: str) -> bool:
    alert_file = state_dir / "alerts.jsonl"
    if not alert_file.exists():
        return False
    key = sha256_text(condition)
    for line in alert_file.read_text(encoding="utf-8").splitlines():
        if line.strip() and json.loads(line).get("key") == key:
            return True
    return False


# ---------------------------------------------------------------- preflight

def registry_conflicts(registry_db: str, project_id: str, project_root: str, scope_text: str) -> dict[str, Any]:
    """Consulta SOLO LECTURA: replicas la comprobacion de conflicto de work_claims.create_claim."""
    identity = compute_identity_hashes(project_id, project_root, scope_text)
    con = sqlite3.connect("file:" + registry_db + "?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        conflicts = list(con.execute(
            "SELECT claim_id, project_id, project_root, status, lease_expires_at, channel "
            "FROM claims WHERE status='active' AND mode='writer' "
            "AND (project_id=? OR project_root_hash=? OR scope_hash=?) ORDER BY created_at",
            (project_id, identity["projectRootHash"], identity["scopeHash"]),
        ))
    finally:
        con.close()
    return {
        "identity": identity,
        "conflicts": [dict(row) for row in conflicts],
        "clear": not conflicts,
    }


# ------------------------------------------------------------- comandos CLI

def cmd_checklist(args: argparse.Namespace) -> int:
    text = (
        "GUARD24-7 · CHECKLIST DE APERTURA DE TURNO (obligatoria para DeepSeek 1512/2001 y ChatGPT 1512)\n"
        "==========================================================================\n"
        "1. GOAL 24/7 ARMADO: llama get_goal(); si es null crea el goal de la prioridad del propietario\n"
        "   (software de ahorro + dispatcher/cola/gobernador) con rondas de continuacion y NO lo cierres\n"
        "   hasta tener el software en marcha y usandolo. Un turno que acaba sin goal armado = chat parado.\n"
        "2. NO PISARSE: antes de tocar cualquier proyecto/fichero ejecuta:\n"
        "   python guard24_7/cli.py preflight --registry-db <work-claims.sqlite3> --project-id <id> --root <dir> --scope-file <fichero>\n"
        "   exit 0 = libre (obtener claim propio con inputs+hashes en el registro unico work-claim-v2).\n"
        "   exit 2 = conflicto: no escribir; elegir otra unidad o aportar evidencia al coordinador 01a06515.\n"
        "3. RAM: comprueba que libres >= 1 GiB antes de lanzar procesos; en rojo solo trabajo ligero y vigilancia.\n"
        "4. SIGUIENTE UNIDAD ADMISIBLE: ejecutar la siguiente unidad independiente del carril; si no hay,\n"
        "   vigilancia de bajo consumo + evidencia al coordinador (sin bucles ni relleno).\n"
        "5. AL ACABAR EL TURNO: el goal queda ARMADO (nunca completed/blocked salvo causa real), evidencia\n"
        "   con hashes guardada, y el siguiente turno arranca solo. Ningun chat para por fin de turno,\n"
        "   ausencia del propietario o lote terminado (normas 13-sep-2026).\n"
    )
    if not args.quiet:
        print(text)
    print(canonical_json({"ok": True, "checklistSha256": sha256_text(text), "steps": 5}))
    return 0


def cmd_preflight(args: argparse.Namespace) -> int:
    scope_text = Path(args.scope_file).read_text(encoding="utf-8-sig").strip()
    result = registry_conflicts(args.registry_db, args.project_id, args.root, scope_text)
    result["ok"] = result["clear"]
    result["scopeSha256"] = sha256_text(scope_text)
    print(canonical_json(result))
    return 0 if result["clear"] else 2


def http_check(host: str, port: int, timeout: float = 8.0) -> dict[str, Any]:
    url = f"http://{host}:{port}/"
    started = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return {"up": True, "status": response.status, "ms": round((time.monotonic() - started) * 1000)}
    except Exception as exc:  # noqa: BLE001 — cualquier fallo = caido
        return {"up": False, "error": f"{type(exc).__name__}: {exc}"}


def semantic_fingerprint(checks: dict[str, Any]) -> str:
    # Solo cambios SEMANTICOS cuentan como cambio de estado (RAM numerica volatil no alerta).
    tabs = {k: bool(v.get("up")) for k, v in checks.items() if k.startswith("tab_")}
    registry_ok = bool(checks.get("registry", {}).get("readable"))
    ram_state = checks.get("ram", {}).get("verdict")
    restarts = {k: v.get("restart") for k, v in checks.items() if isinstance(v, dict) and "restart" in v}
    return canonical_json({"tabs": tabs, "registry_ok": registry_ok, "ram": ram_state, "restarts": restarts})


def cmd_watch(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir)
    targets = [tuple(t.split(":")) for t in args.targets.split(",")]
    targets = [(host, int(port)) for host, port in targets]
    tick = 0
    fingerprint_file = state_dir / "last-fingerprint.json"
    last_fingerprint = ""
    if fingerprint_file.exists():
        last_fingerprint = fingerprint_file.read_text(encoding="utf-8").strip()
    restarts: dict[str, list[str]] = {}
    while True:
        tick += 1
        now = utc_now_text()
        checks: dict[str, Any] = {}
        # pestanas
        for host, port in targets:
            key = f"tab_{port}"
            result = http_check(host, port)
            checks[key] = {"up": result["up"], "status": result.get("status"), "error": result.get("error")}
        # RAM
        ram = read_ram()
        verdict = ram_verdict(ram)
        checks["ram"] = {"verdict": verdict, "free_gib": round(ram["free_gib"], 3),
                         "used_gib": round(ram["used_gib"], 3)}
        # registro
        con = None
        try:
            con = sqlite3.connect("file:" + args.registry_db + "?mode=ro", uri=True)
            counts = {row[0]: row[1] for row in con.execute(
                "SELECT status, COUNT(*) FROM claims GROUP BY status").fetchall()}
            checks["registry"] = {"readable": True, "counts": counts}
        except Exception as exc:  # noqa: BLE001
            checks["registry"] = {"readable": False, "error": f"{type(exc).__name__}: {exc}"}
        finally:
            if con is not None:
                con.close()
        # rearranque de pestanas caidas (con gobernador de RAM y cooldown)
        for host, port in targets:
            key = f"tab_{port}"
            if not checks[key]["up"] and args.restart_enabled:
                day = now[:10]
                attempted = restarts.setdefault(day, [])
                last = max((t for t in attempted if t), default=None)
                cooldown_ok = last is None or (time.time() - _parse_ts(last)) >= RESTART_COOLDOWN_S
                if (len(attempted) < MAX_RESTARTS_PER_DAY and cooldown_ok
                        and ram["free_gib"] >= FLOOR_FREE_GIB and args.restart_command):
                    checks[key]["restart"] = "executed"
                    attempted.append(now)
                    _launch_restart(args.restart_command, state_dir, port)
                else:
                    checks[key]["restart"] = "blocked"
                    checks[key]["restart_reason"] = (
                        "RAM_ROJO" if ram["free_gib"] < FLOOR_FREE_GIB else
                        ("cooldown" if not cooldown_ok else "max_restarts_dia"))
        fingerprint = semantic_fingerprint(checks)
        append_heartbeat(state_dir, {"kind": "watch-local", "at": now, "tick": tick, "checks": checks})
        # una sola alerta por cambio de estado (persistente entre invocaciones)
        if last_fingerprint and fingerprint != last_fingerprint:
            append_alert(state_dir, "watch-state-changed", {
                "previous": json.loads(last_fingerprint) if last_fingerprint else {},
                "current": json.loads(fingerprint),
            })
        last_fingerprint = fingerprint
        fingerprint_file.write_text(fingerprint, encoding="utf-8")
        print(canonical_json({"tick": tick, "at": now, "ram": verdict, "checks": checks}))
        if args.max_ticks and tick >= args.max_ticks:
            return 0
        time.sleep(args.interval_min * 60)


def _parse_ts(value: str) -> float:
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _launch_restart(command: str, state_dir: Path, port: int) -> None:
    import subprocess
    flags = 0
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    try:
        proc = subprocess.Popen(command, shell=True, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=flags)
        append_alert(state_dir, f"tab_{port}-restarted", {"pid": proc.pid, "at": utc_now_text()})
    except Exception as exc:  # noqa: BLE001
        append_alert(state_dir, f"tab_{port}-restart-failed", {"error": f"{type(exc).__name__}: {exc}"})


def cmd_verify(args: argparse.Namespace) -> int:
    result = verify_chain(Path(args.state_dir))
    print(canonical_json(result))
    return 0 if result["ok"] else 3


def cmd_cloud_heartbeat(args: argparse.Namespace) -> int:
    state_dir = Path(args.state_dir)
    checks: dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
    }
    import shutil
    usage = shutil.disk_usage(str(state_dir or "."))
    checks["disk_free_gib"] = round(usage.free / 1024.0 ** 3, 3)
    if Path("/proc/uptime").exists():
        checks["uptime_s"] = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
    checks["chain_ok"] = verify_chain(state_dir)["ok"]
    record = {"kind": "cloud-heartbeat", "at": utc_now_text(), "checks": checks}
    append_heartbeat(state_dir, record)
    print(canonical_json({"ok": True, "heartbeat": record}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    chk = sub.add_parser("checklist", help="checklist obligatoria de apertura de turno")
    chk.add_argument("--quiet", action="store_true")
    chk.set_defaults(func=cmd_checklist)

    pre = sub.add_parser("preflight", help="chequeo SOLO LECTURA de conflicto contra work-claim-v2")
    pre.add_argument("--registry-db", required=True)
    pre.add_argument("--project-id", required=True)
    pre.add_argument("--root", required=True)
    pre.add_argument("--scope-file", required=True)
    pre.set_defaults(func=cmd_preflight)

    w = sub.add_parser("watch", help="vigilancia 24/7 de bajo consumo (modo local)")
    w.add_argument("--interval-min", type=int, default=10)
    w.add_argument("--max-ticks", type=int, default=0, help="0 = indefinido")
    w.add_argument("--targets", default="127.0.0.1:3081,127.0.0.1:3082")
    w.add_argument("--registry-db", required=True)
    w.add_argument("--state-dir", required=True)
    w.add_argument("--restart-enabled", action="store_true")
    w.add_argument("--restart-command", default="")
    w.set_defaults(func=cmd_watch)

    ver = sub.add_parser("verify-heartbeat", help="verifica la cadena de hashes del heartbeat")
    ver.add_argument("--state-dir", required=True)
    ver.set_defaults(func=cmd_verify)

    cloud = sub.add_parser("cloud-heartbeat", help="latido de nube (Actions cron / Codespace)")
    cloud.add_argument("--state-dir", required=True)
    cloud.set_defaults(func=cmd_cloud_heartbeat)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
