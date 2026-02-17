#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import json
import os
import sys
import tempfile
import shutil
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# File lock for DB warmup (Linux)
try:
    import fcntl  # type: ignore
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore

# Сопоставление уровней критичности (фильтр вывода)
SEVERITY_LEVELS = {
    1: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"],  # UNKNOWN+
    2: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],            # LOW+
    3: ["MEDIUM", "HIGH", "CRITICAL"],                   # MEDIUM+
    4: ["HIGH", "CRITICAL"],                             # HIGH+
    5: ["CRITICAL"],                                     # CRITICAL
}

DEFAULT_TRIVY_TIMEOUT = "10m"

def _now_iso() -> str:
    return datetime.now().isoformat()

def _safe_int(v: Any, default: int) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default

def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)

def _stdout(msg: str) -> None:
    print(msg, file=sys.stdout, flush=True)

def _looks_like_permission_issue(stderr_text: str) -> bool:
    s = (stderr_text or "").lower()
    needles = [
        "permission denied",
        "cannot connect to the docker daemon",
        "dial unix /var/run/docker.sock",
        "got permission denied",
        "operation not permitted",
        "access denied",
    ]
    return any(n in s for n in needles)

def _unknown_flag(stderr_text: str, flag: str) -> bool:
    s = (stderr_text or "").lower()
    return ("unknown flag" in s) and (flag.lower() in s)


def _looks_like_db_issue(stderr_text: str) -> bool:
    s = (stderr_text or "").lower()
    needles = [
        "db corrupted",
        "vulnerability db",
        "error in vulnerability db initialize",
        "failed to download vulnerability db",
        "oci artifact error",
        "trivy.db",
        "metadata.json",
        "unable to open database file",
        "database initialize",
        "db error",
    ]
    return any(n in s for n in needles)

def _looks_like_missing_db_path(stderr_text: str) -> bool:
    s = (stderr_text or "").lower()
    return ("no such file or directory" in s) and (("trivy.db" in s) or ("/db/" in s))


class TrivyScanner:
    """
    Оптимизация без изменения бизнес-логики:
    - вход: 2 файла (input_images.txt и input_images_files.txt)
    - режим: remote / local / both
    - вывод в консоль: прогресс + сводка (без печати большого JSON)
    - финальный JSON-отчёт сохраняется, в stdout печатается только имя файла
    """

    def __init__(
        self,
        mode: Optional[str] = None,
        jobs_remote: int = 2,
        jobs_local: int = 1,
        trivy_timeout: str = DEFAULT_TRIVY_TIMEOUT,
    ) -> None:
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.mode = mode  # remote | local | both | None(меню)
        self.jobs_remote = max(1, jobs_remote)
        self.jobs_local = max(1, jobs_local)
        self.trivy_timeout = trivy_timeout

        # Выделенный cache-dir, чтобы реже требовался sudo и было быстрее
        self.cache_dir = os.path.join(self.script_dir, ".trivy_cache")
        os.makedirs(self.cache_dir, exist_ok=True)

        # DB warmup + anti-race:
        # - Trivy не безопасен при параллельном обновлении DB в одном cache-dir.
        # - Поэтому DB скачиваем/чинем ОДИН раз под файловой блокировкой и далее сканируем с --skip-db-update.
        self._db_ready = False
        self._java_db_ready = False
        self._db_prepare_lock = asyncio.Lock()
        self._db_lock_path = os.path.join(self.cache_dir, ".trivy_db.lock")

        # Подготовим поддиректории (уменьшает шанс гонок на mkdir/chmod в Trivy)
        os.makedirs(os.path.join(self.cache_dir, "db"), exist_ok=True)
        os.makedirs(os.path.join(self.cache_dir, "java-db"), exist_ok=True)

    # ------------------------- UI / INPUT -------------------------

    def show_menu(self) -> str:
        _stderr("=" * 60)
        _stderr("🔐 ADVANCED DOCKER IMAGES SCANNER")
        _stderr("=" * 60)
        _stderr("\nВыберите режим работы:")
        _stderr("1. 📡 Сканировать удаленные Docker образы (input_images.txt)")
        _stderr("2. 🔧 Собрать и просканировать локальные Dockerfile (input_images_files.txt)")
        _stderr("3. 🧩 Оба режима (remote + local)")

        while True:
            try:
                choice = input("\nВыберите режим (1/2/3): ").strip()
                if choice == "1":
                    return "remote"
                if choice == "2":
                    return "local"
                if choice == "3":
                    return "both"
                _stderr("❌ Неверный выбор. Введите 1, 2 или 3")
            except (KeyboardInterrupt, EOFError):
                _stderr("\n👋 Выход")
                sys.exit(0)

    def parse_input_file(self, file_path: str, mode: str) -> Tuple[int, List[str]]:
        """
        Парсит файл с образами или Dockerfile путями.
        mode: "images" - для удаленных образов, "files" - для путей к Dockerfile
        """
        items: List[str] = []
        severity_level = 4  # По умолчанию HIGH+

        if not os.path.exists(file_path):
            _stderr(f"❌ Файл {file_path} не найден")
            return severity_level, items

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue

                    if line.lower().startswith("severity="):
                        sev = _safe_int(line.split("=", 1)[1], 4)
                        severity_level = sev if 1 <= sev <= 5 else 4
                        continue

                    items.append(line)

            mode_name = "образов" if mode == "images" else "Dockerfile"
            _stderr(f"📋 Найдено {len(items)} {mode_name} для сканирования")
            _stderr(f"📊 Уровень критичности: {severity_level} (включая {SEVERITY_LEVELS.get(severity_level, [])})")

        except Exception as e:
            _stderr(f"❌ Ошибка чтения файла {file_path}: {e}")

        return severity_level, items

    # ------------------------- DOCKER BUILD / CLEANUP -------------------------

    async def _run_proc(
        self,
        cmd: List[str],
        cwd: Optional[str] = None,
        timeout_s: Optional[int] = None,
        stdout_pipe: bool = False,
        stderr_pipe: bool = True,
    ) -> Tuple[int, str, str]:
        stdout_opt = asyncio.subprocess.PIPE if stdout_pipe else asyncio.subprocess.DEVNULL
        stderr_opt = asyncio.subprocess.PIPE if stderr_pipe else asyncio.subprocess.PIPE

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=stdout_opt,
            stderr=stderr_opt,
        )
        try:
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return 124, "", "timeout"

        out = (out_b or b"").decode("utf-8", errors="replace")
        err = (err_b or b"").decode("utf-8", errors="replace")
        return int(proc.returncode or 0), out, err

    async def build_docker_image(self, dockerfile_path: str, image_name: str) -> Tuple[bool, str]:
        dockerfile_dir = os.path.dirname(dockerfile_path)
        dockerfile_name = os.path.basename(dockerfile_path)

        _stderr(f"  📦 Сборка образа из: {dockerfile_path}")
        # -q: минимальный вывод, быстрее и меньше нагрузки на stdout/stderr
        cmd = ["docker", "build", "-q", "-f", dockerfile_name, "-t", image_name, "."]

        rc, out, err = await self._run_proc(cmd, cwd=dockerfile_dir, timeout_s=1800, stdout_pipe=True, stderr_pipe=True)
        if rc != 0:
            msg = (err.strip() or out.strip() or "Неизвестная ошибка сборки")
            msg = "\n".join(msg.splitlines()[-30:])
            return False, msg

        _stderr(f"  ✅ Образ собран: {image_name}")
        return True, image_name

    async def remove_docker_image(self, image_name: str) -> None:
        cmd = ["docker", "rmi", "-f", image_name]
        await self._run_proc(cmd, timeout_s=300, stdout_pipe=False, stderr_pipe=False)
        _stderr(f"  🗑️  Образ удален: {image_name}")

    
    # ------------------------- TRIVY DB (WARMUP / REPAIR) -------------------------

    def _vuln_db_path(self) -> str:
        return os.path.join(self.cache_dir, "db", "trivy.db")

    def _vuln_db_meta_path(self) -> str:
        return os.path.join(self.cache_dir, "db", "metadata.json")

    def _java_db_dir(self) -> str:
        return os.path.join(self.cache_dir, "java-db")

    def _cache_has_vuln_db(self) -> bool:
        p = self._vuln_db_path()
        try:
            return os.path.exists(p) and os.path.getsize(p) > 1024
        except Exception:
            return False

    def _cache_has_java_db(self) -> bool:
        d = self._java_db_dir()
        try:
            if not os.path.isdir(d):
                return False
            # Любой непустой файл/директория в java-db считаем признаком наличия БД
            return any(os.scandir(d))
        except Exception:
            return False

    async def _trivy_download_db_only(self) -> Tuple[bool, str]:
        """Скачивает vulnerability DB (и при возможности Java DB) в cache-dir.

        Важно: разные версии Trivy по-разному поддерживают флаги/сабкоманды.
        Поэтому пробуем несколько вариантов, затем fallback на «dummy scan» маленького образа,
        который гарантированно триггерит загрузку DB.
        """
        # Уже есть — не трогаем
        if self._cache_has_vuln_db():
            self._db_ready = True
            self._java_db_ready = self._cache_has_java_db()
            return True, "db already present"

        timeout_s = 900  # 15 минут на скачивание/инициализацию DB (обычно быстрее)

        candidates: List[List[str]] = [
            ["trivy", "--cache-dir", self.cache_dir, "db", "--download-db-only"],
            ["trivy", "db", "--download-db-only", "--cache-dir", self.cache_dir],
            ["trivy", "--cache-dir", self.cache_dir, "image", "--download-db-only"],
            ["trivy", "image", "--download-db-only", "--cache-dir", self.cache_dir],
        ]

        # 1) Пробуем download-db-only без таргета
        for cmd in candidates:
            rc, _out, err = await self._run_proc(cmd, timeout_s=timeout_s, stdout_pipe=False, stderr_pipe=True)
            if rc == 0 and self._cache_has_vuln_db():
                self._db_ready = True
                break

            s = (err or "").lower()
            # Некоторые версии требуют таргет для 'image --download-db-only'
            if ("requires at least 1 arg" in s) or ("accepts 1 arg" in s) or ("missing argument" in s):
                cmd2 = cmd + ["alpine:3.19"]
                rc2, _out2, err2 = await self._run_proc(cmd2, timeout_s=timeout_s, stdout_pipe=False, stderr_pipe=True)
                if rc2 == 0 and self._cache_has_vuln_db():
                    self._db_ready = True
                    break

            # Если флаг неизвестен — пробуем следующий вариант
            if "unknown flag" in s and "--download-db-only" in s:
                continue

        # 2) Fallback: dummy scan малого образа (триггерит загрузку DB)
        if not self._db_ready:
            dummy_cmd = ["trivy", "image", "--quiet", "--no-progress", "--timeout", "5m", "--cache-dir", self.cache_dir, "alpine:3.19"]
            rc, _out, err = await self._run_proc(dummy_cmd, timeout_s=timeout_s, stdout_pipe=False, stderr_pipe=True)
            if rc == 0 and self._cache_has_vuln_db():
                self._db_ready = True
            else:
                return False, (err.strip() or "Не удалось подготовить Trivy DB")

        # 3) Попытка скачать Java DB (если поддерживается), чтобы потом сканировать параллельно без гонок
        self._java_db_ready = self._cache_has_java_db()
        if not self._java_db_ready:
            java_candidates: List[List[str]] = [
                ["trivy", "--cache-dir", self.cache_dir, "image", "--download-java-db-only"],
                ["trivy", "image", "--download-java-db-only", "--cache-dir", self.cache_dir],
            ]
            for cmd in java_candidates:
                rc, _out, err = await self._run_proc(cmd, timeout_s=timeout_s, stdout_pipe=False, stderr_pipe=True)
                if rc == 0:
                    self._java_db_ready = self._cache_has_java_db()
                    if self._java_db_ready:
                        break
                s = (err or "").lower()
                if "unknown flag" in s and "--download-java-db-only" in s:
                    break  # нет смысла перебирать

        return True, "db ready"

    async def repair_trivy_databases(self) -> Tuple[bool, str]:
        """Чистит поврежденные DB и скачивает заново."""
        # Сносим только DB (не весь scan-cache), чтобы не терять пользу от кэша слоёв/артефактов
        try:
            shutil.rmtree(os.path.join(self.cache_dir, "db"), ignore_errors=True)
            shutil.rmtree(os.path.join(self.cache_dir, "java-db"), ignore_errors=True)
            os.makedirs(os.path.join(self.cache_dir, "db"), exist_ok=True)
            os.makedirs(os.path.join(self.cache_dir, "java-db"), exist_ok=True)
        except Exception as e:
            return False, f"Не удалось очистить кэш DB: {e}"

        # Сброс флагов
        self._db_ready = False
        self._java_db_ready = False
        ok, msg = await self._trivy_download_db_only()
        return ok, msg

    async def ensure_trivy_databases(self) -> Tuple[bool, str]:
        """Гарантирует, что DB подготовлена 1 раз под файловой блокировкой."""
        async with self._db_prepare_lock:
            if self._db_ready and self._cache_has_vuln_db():
                self._java_db_ready = self._cache_has_java_db()
                return True, "db already ready"

            # Файловая блокировка нужна, если вы запустите скрипт в нескольких терминалах одновременно
            try:
                os.makedirs(self.cache_dir, exist_ok=True)
                with open(self._db_lock_path, "w", encoding="utf-8") as lock_f:
                    if fcntl is not None:
                        fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)

                    ok, msg = await self._trivy_download_db_only()

                    if fcntl is not None:
                        fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)

                    return ok, msg
            except Exception as e:
                return False, f"DB warmup error: {e}"

# ------------------------- TRIVY SCAN (FAST PATH) -------------------------

    async def _trivy_scan_once(
        self,
        target: str,
        use_sudo: bool,
        timeout_s: int,
        allow_no_progress: bool = True,
        allow_quiet: bool = True,
        allow_timeout_flag: bool = True,
        allow_skip_db_update: bool = True,
        allow_skip_java_db_update: bool = True,
    ) -> Tuple[int, str]:
        """
        Trivy пишет JSON сразу в temp-файл (без огромного stdout).
        Если trivy старый и флаг не поддерживается — пробуем без него.
        """
        tmp_fd, tmp_path = tempfile.mkstemp(prefix="trivy_", suffix=".json")
        os.close(tmp_fd)

        cmd = ["trivy", "image"]

        if allow_quiet:
            cmd.append("--quiet")
        if allow_no_progress:
            cmd.append("--no-progress")
        if allow_timeout_flag:
            cmd += ["--timeout", self.trivy_timeout]

        # Важно для параллельного скана: запрещаем Trivy обновлять DB внутри каждого процесса.
        # DB подготавливается 1 раз через ensure_trivy_databases().
        if allow_skip_db_update:
            cmd.append("--skip-db-update")
        if allow_skip_java_db_update:
            cmd.append("--skip-java-db-update")

        cmd += [
            "--cache-dir", self.cache_dir,
            "--format", "json",
            "--output", tmp_path,
            target,
        ]

        full_cmd = (["sudo"] + cmd) if use_sudo else cmd
        rc, _out, err = await self._run_proc(full_cmd, timeout_s=timeout_s, stdout_pipe=False, stderr_pipe=True)

        if rc != 0:
            # fallback для старых trivy (unknown flag)
            if allow_no_progress and _unknown_flag(err, "--no-progress"):
                try: os.unlink(tmp_path)
                except Exception: pass
                return await self._trivy_scan_once(target, use_sudo, timeout_s, allow_no_progress=False, allow_quiet=allow_quiet, allow_timeout_flag=allow_timeout_flag, allow_skip_db_update=allow_skip_db_update, allow_skip_java_db_update=allow_skip_java_db_update)

            if allow_quiet and _unknown_flag(err, "--quiet"):
                try: os.unlink(tmp_path)
                except Exception: pass
                return await self._trivy_scan_once(target, use_sudo, timeout_s, allow_no_progress=allow_no_progress, allow_quiet=False, allow_timeout_flag=allow_timeout_flag, allow_skip_db_update=allow_skip_db_update, allow_skip_java_db_update=allow_skip_java_db_update)

            if allow_timeout_flag and _unknown_flag(err, "--timeout"):
                try: os.unlink(tmp_path)
                except Exception: pass
                return await self._trivy_scan_once(target, use_sudo, timeout_s, allow_no_progress=allow_no_progress, allow_quiet=allow_quiet, allow_timeout_flag=False, allow_skip_db_update=allow_skip_db_update, allow_skip_java_db_update=allow_skip_java_db_update)

            if allow_skip_db_update and _unknown_flag(err, "--skip-db-update"):
                try: os.unlink(tmp_path)
                except Exception: pass
                return await self._trivy_scan_once(
                    target, use_sudo, timeout_s,
                    allow_no_progress=allow_no_progress,
                    allow_quiet=allow_quiet,
                    allow_timeout_flag=allow_timeout_flag,
                    allow_skip_db_update=False,
                    allow_skip_java_db_update=allow_skip_java_db_update,
                )

            if allow_skip_java_db_update and _unknown_flag(err, "--skip-java-db-update"):
                try: os.unlink(tmp_path)
                except Exception: pass
                return await self._trivy_scan_once(
                    target, use_sudo, timeout_s,
                    allow_no_progress=allow_no_progress,
                    allow_quiet=allow_quiet,
                    allow_timeout_flag=allow_timeout_flag,
                    allow_skip_db_update=allow_skip_db_update,
                    allow_skip_java_db_update=False,
                )


            try: os.unlink(tmp_path)
            except Exception: pass
            return rc, (err.strip() or "Ошибка сканирования trivy")

        return 0, tmp_path


    async def scan_docker_image(self, image_name_or_url: str) -> Optional[Dict[str, Any]]:
        timeout_s = 1800  # 30 минут на один образ

        # Важный preflight: DB должна быть подготовлена ДО параллельных сканов.
        ok, msg = await self.ensure_trivy_databases()
        if not ok:
            _stderr(f"❌ Не удалось подготовить Trivy DB: {msg}")
            return None

        async def _do_scan() -> Tuple[int, str]:
            # 1) fast path без sudo
            rc1, payload1 = await self._trivy_scan_once(
                image_name_or_url,
                use_sudo=False,
                timeout_s=timeout_s,
                allow_skip_db_update=True,
                allow_skip_java_db_update=self._java_db_ready,
            )
            # 2) retry с sudo только если похоже на права
            if rc1 != 0 and _looks_like_permission_issue(payload1):
                rc2, payload2 = await self._trivy_scan_once(
                    image_name_or_url,
                    use_sudo=True,
                    timeout_s=timeout_s,
                    allow_skip_db_update=True,
                    allow_skip_java_db_update=self._java_db_ready,
                )
                return rc2, payload2
            return rc1, payload1

        rc, payload = await _do_scan()

        # Если DB сломалась/не докачалась (обычно из-за гонки при параллельных обновлениях) — чиним и повторяем 1 раз
        if rc != 0 and (_looks_like_db_issue(payload) or _looks_like_missing_db_path(payload)):
            _stderr("⚠️  Обнаружена проблема с Trivy DB (коррупция/недокачка). Выполняю repair и повтор.")
            ok2, msg2 = await self.repair_trivy_databases()
            if ok2:
                rc, payload = await _do_scan()
            else:
                _stderr(f"❌ Repair DB не удался: {msg2}")

        if rc != 0:
            _stderr(f"❌ Ошибка сканирования {image_name_or_url}: {payload[:500]}")
            return None

        json_path = payload
        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as f:
                return json.load(f)
        except Exception as e:
            _stderr(f"❌ Ошибка чтения JSON результата trivy: {e}")
            return None
        finally:
            try:
                os.unlink(json_path)
            except Exception:
                pass

    # ------------------------- PARSING / FORMATTING -------------------------

    def classify_component_type(self, result_data: Dict[str, Any], vulnerability: Optional[Dict[str, Any]] = None, secret: Optional[Dict[str, Any]] = None) -> str:
        target = (result_data.get("Target") or "")
        class_type = (result_data.get("Class") or "")
        type_name = (result_data.get("Type") or "")

        if secret or class_type == "secret":
            return "Secret"

        if vulnerability:
            pkg_name = (vulnerability.get("PkgName") or "").lower()
            pkg_path = (vulnerability.get("PkgPath") or "").lower()

            if class_type in ["os-pkgs", "os"] or type_name in ["debian", "ubuntu", "alpine", "centos", "rhel", "amazon"]:
                return f"{type_name.capitalize()}-package"

            if class_type == "lang-pkgs":
                if type_name == "gobinary" or "go.mod" in pkg_path or "/go/" in pkg_path:
                    return "Go-package"
                if type_name == "python-pkg" or ".py" in pkg_name or "/python/" in pkg_path:
                    return "Python-package"
                if type_name == "node-pkg" or "node_modules" in pkg_path or "/npm/" in pkg_path:
                    return "NodeJS-package"
                if type_name == "java" or ".jar" in pkg_name or "/java/" in pkg_path:
                    return "Java-package"
                if type_name == "php" or ".php" in pkg_name:
                    return "PHP-package"
                if type_name == "ruby" or ".gem" in pkg_name:
                    return "Ruby-package"
                if type_name == "rust" or ".crate" in pkg_name:
                    return "Rust-package"
                if type_name == "dotnet" or ".dll" in pkg_name:
                    return "DotNet-package"
                if type_name == "conda":
                    return "Conda-package"
                return f"{type_name}-package" if type_name else "Unknown-language-package"

        if class_type == "config" or "config" in target.lower():
            return "Configuration"
        if class_type == "binary":
            return "Binary"
        if type_name:
            return f"{type_name}-component"
        return "Unknown-component"

    def analyze_and_format_vulnerabilities(self, data: Dict[str, Any], severity_level: int) -> Tuple[Dict[str, Any], Dict[str, Dict[str, int]]]:
        included_levels = SEVERITY_LEVELS.get(severity_level, ["HIGH", "CRITICAL"])
        component_structure: Dict[str, Any] = {}
        statistics: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        if not data:
            return component_structure, statistics

        for result_data in data.get("Results", []) or []:
            for vuln in (result_data.get("Vulnerabilities") or []):
                severity = (vuln.get("Severity") or "UNKNOWN").upper()
                if severity not in included_levels:
                    continue

                component_type = self.classify_component_type(result_data, vulnerability=vuln)
                component_structure.setdefault(component_type, {})
                component_structure[component_type].setdefault(severity, [])

                vuln_entry: Dict[str, Any] = {
                    "vuln_id": vuln.get("VulnerabilityID", ""),
                    "installed_vers": vuln.get("InstalledVersion", ""),
                    "fixed": vuln.get("FixedVersion", ""),
                    "library": vuln.get("PkgName", ""),
                    "type_detail": result_data.get("Type", ""),
                    "class_detail": result_data.get("Class", ""),
                    "target": result_data.get("Target", ""),
                    "type": "vulnerability",
                }

                for field in ["Title", "Description", "CVSS", "SeveritySource", "PrimaryURL"]:
                    if field in vuln and vuln[field]:
                        vuln_entry[field.lower()] = vuln[field]

                component_structure[component_type][severity].append(vuln_entry)
                statistics[component_type][severity] += 1

            for secret in (result_data.get("Secrets") or []):
                severity = (secret.get("Severity") or "UNKNOWN").upper()
                if severity not in included_levels:
                    continue

                component_type = "Secret"
                component_structure.setdefault(component_type, {})
                component_structure[component_type].setdefault(severity, [])

                secret_entry = {
                    "secret_id": secret.get("RuleID", ""),
                    "category": secret.get("Category", ""),
                    "title": secret.get("Title", ""),
                    "target": result_data.get("Target", ""),
                    "start_line": secret.get("StartLine", ""),
                    "end_line": secret.get("EndLine", ""),
                    "match": secret.get("Match", ""),
                    "type_detail": result_data.get("Type", ""),
                    "class_detail": result_data.get("Class", ""),
                    "type": "secret",
                }

                component_structure[component_type][severity].append(secret_entry)
                statistics[component_type][severity] += 1

        for secret in (data.get("Secrets") or []):
            severity = (secret.get("Severity") or "UNKNOWN").upper()
            if severity not in included_levels:
                continue
            component_type = "Secret"
            component_structure.setdefault(component_type, {})
            component_structure[component_type].setdefault(severity, [])
            component_structure[component_type][severity].append({
                "secret_id": secret.get("RuleID", ""),
                "category": secret.get("Category", ""),
                "title": secret.get("Title", ""),
                "target": secret.get("Target", ""),
                "start_line": secret.get("StartLine", ""),
                "end_line": secret.get("EndLine", ""),
                "match": secret.get("Match", ""),
                "type": "secret",
            })
            statistics[component_type][severity] += 1

        return component_structure, statistics

    def generate_summary_report(self, statistics: Dict[str, Dict[str, int]]) -> str:
        lines: List[str] = []
        lines.append("\n📊 СВОДКА ПО ТИПАМ КОМПОНЕНТОВ:")
        lines.append("=" * 60)

        total_vulns = 0
        total_secrets = 0

        if "Secret" in statistics:
            secret_stats = statistics["Secret"]
            secret_total = sum(secret_stats.values())
            total_secrets = secret_total
            if secret_total > 0:
                lines.append(f"\n🔐 SECRETS (Секреты): {secret_total} находок")
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
                    if secret_stats.get(sev, 0) > 0:
                        count = secret_stats[sev]
                        pct = (count / secret_total) * 100 if secret_total else 0
                        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}.get(sev, "")
                        lines.append(f"  {emoji} {sev}: {count} ({pct:.1f}%)")

        for comp_type in sorted(statistics.keys()):
            if comp_type == "Secret":
                continue
            comp_stats = statistics[comp_type]
            comp_total = sum(comp_stats.values())
            total_vulns += comp_total
            if comp_total > 0:
                lines.append(f"\n{comp_type}: {comp_total} уязвимостей")
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
                    if comp_stats.get(sev, 0) > 0:
                        count = comp_stats[sev]
                        pct = (count / comp_total) * 100 if comp_total else 0
                        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "UNKNOWN": "⚪"}.get(sev, "")
                        lines.append(f"  {emoji} {sev}: {count} ({pct:.1f}%)")

        comp_types_count = len([k for k in statistics.keys() if k != "Secret"])
        lines.append(f"\n📈 ИТОГО: {total_vulns} уязвимостей в {comp_types_count} типах компонентов")
        if total_secrets > 0:
            lines.append(f"🔐 СЕКРЕТЫ: {total_secrets} находок")

        return "\n".join(lines)

    # ------------------------- MODES (REMOTE / LOCAL) -------------------------

    async def _scan_one_remote(
        self,
        idx: int,
        total: int,
        image_url: str,
        severity_level: int,
        sem: asyncio.Semaphore,
    ) -> Tuple[Dict[str, Any], Dict[str, Dict[str, int]]]:
        async with sem:
            loop = asyncio.get_running_loop()
            t0 = loop.time()
            _stderr(f"\n[{idx}/{total}] 📡 {image_url}")

            scan_data = await self.scan_docker_image(image_url)
            if not scan_data:
                _stderr("  ❌ Ошибка при сканировании")
                return ({
                    "image": image_url,
                    "error": "Не удалось просканировать образ",
                    "scan_timestamp": _now_iso(),
                    "scan_type": "remote",
                }, defaultdict(lambda: defaultdict(int)))

            component_structure, statistics = self.analyze_and_format_vulnerabilities(scan_data, severity_level)

            image_result: Dict[str, Any] = {
                "image": image_url,
                "scan_timestamp": _now_iso(),
                "severity_level": severity_level,
                "included_severities": SEVERITY_LEVELS.get(severity_level, []),
                "scan_type": "remote",
            }
            for comp_type, sev_data in component_structure.items():
                image_result[comp_type] = sev_data

            secrets_total = sum(statistics.get("Secret", {}).values())
            vulns_total = sum(sum(stats.values()) for c, stats in statistics.items() if c != "Secret")
            dt = loop.time() - t0

            comp_summary = []
            for comp_type, stats in statistics.items():
                ct = sum(stats.values())
                if ct > 0:
                    comp_summary.append(f"{comp_type}:{ct}")
            _stderr(f"  ✅ Vulns={vulns_total}, Secrets={secrets_total}, Time={dt:.1f}s")
            if comp_summary:
                _stderr(f"  📦 Components: {', '.join(comp_summary[:10])}{' ...' if len(comp_summary) > 10 else ''}")

            return image_result, statistics

    async def scan_remote_images(self) -> List[Dict[str, Any]]:
        input_file = os.path.join(self.script_dir, "input_images.txt")
        if not os.path.exists(input_file):
            _stderr(f"❌ Файл {input_file} не найден")
            _stderr("📝 Создайте файл input_images.txt, пример:")
            _stderr("# severity=4\n# registry.example.com/image@sha256:....\n")
            return []

        severity_level, images = self.parse_input_file(input_file, "images")
        if not images:
            _stderr("❌ Не найдено образов для сканирования")
            return []

        total = len(images)
        _stderr(f"\n🚀 Начинаю сканирование {total} удаленных образов...")
        _stderr(f"⚙️  Параллельность (remote jobs): {self.jobs_remote}")
        _stderr(f"📁 Trivy cache-dir: {self.cache_dir}")

        ok_db, msg_db = await self.ensure_trivy_databases()
        if not ok_db:
            _stderr(f"❌ Не удалось подготовить Trivy DB: {msg_db}")
            _stderr("💡 Быстрый фикс руками: trivy clean --vuln-db --java-db  (или rm -rf .trivy_cache/db .trivy_cache/java-db)")
            return []

        sem = asyncio.Semaphore(self.jobs_remote)
        tasks = [self._scan_one_remote(i + 1, total, images[i], severity_level, sem) for i in range(total)]
        pairs = await asyncio.gather(*tasks)

        results: List[Dict[str, Any]] = []
        overall_statistics: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for image_result, stats in pairs:
            results.append(image_result)
            for comp_type, sev_map in stats.items():
                for sev, count in sev_map.items():
                    overall_statistics[comp_type][sev] += count

        _stderr(self.generate_summary_report(overall_statistics))
        return results

    async def _scan_one_local(
        self,
        idx: int,
        total: int,
        dockerfile_path: str,
        severity_level: int,
        sem: asyncio.Semaphore,
    ) -> Tuple[Dict[str, Any], Dict[str, Dict[str, int]]]:
        async with sem:
            loop = asyncio.get_running_loop()
            _stderr(f"\n[{idx}/{total}] 🔧 {dockerfile_path}")

            if not os.path.exists(dockerfile_path):
                _stderr("  ❌ Dockerfile не найден")
                return ({
                    "dockerfile": dockerfile_path,
                    "error": "Файл не найден",
                    "scan_timestamp": _now_iso(),
                    "scan_type": "local",
                }, defaultdict(lambda: defaultdict(int)))

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            dir_name = os.path.basename(os.path.dirname(dockerfile_path)) or "dockerfile"
            # Приводим имя директории к нижнему регистру
            dir_name_lower = dir_name.lower()
            image_name = f"local_scan_{dir_name_lower}_{timestamp}:latest"

            t_build0 = loop.time()
            ok, msg = await self.build_docker_image(dockerfile_path, image_name)
            build_dt = loop.time() - t_build0
            if not ok:
                _stderr(f"  ❌ Ошибка сборки (Time={build_dt:.1f}s): {msg}")
                return ({
                    "dockerfile": dockerfile_path,
                    "error": f"Ошибка сборки: {msg}",
                    "scan_timestamp": _now_iso(),
                    "scan_type": "local",
                }, defaultdict(lambda: defaultdict(int)))

            t_scan0 = loop.time()
            _stderr("  🔍 Сканирование образа...")
            scan_data = await self.scan_docker_image(image_name)
            scan_dt = loop.time() - t_scan0

            try:
                if not scan_data:
                    _stderr(f"  ❌ Ошибка при сканировании (Build={build_dt:.1f}s, Scan={scan_dt:.1f}s)")
                    return ({
                        "dockerfile": dockerfile_path,
                        "image": image_name,
                        "error": "Не удалось просканировать образ",
                        "scan_timestamp": _now_iso(),
                        "scan_type": "local",
                    }, defaultdict(lambda: defaultdict(int)))

                component_structure, statistics = self.analyze_and_format_vulnerabilities(scan_data, severity_level)

                image_result: Dict[str, Any] = {
                    "dockerfile": dockerfile_path,
                    "image": image_name,
                    "scan_timestamp": _now_iso(),
                    "severity_level": severity_level,
                    "included_severities": SEVERITY_LEVELS.get(severity_level, []),
                    "scan_type": "local",
                }
                for comp_type, sev_data in component_structure.items():
                    image_result[comp_type] = sev_data

                secrets_total = sum(statistics.get("Secret", {}).values())
                vulns_total = sum(sum(stats.values()) for c, stats in statistics.items() if c != "Secret")
                _stderr(f"  ✅ Vulns={vulns_total}, Secrets={secrets_total}, Build={build_dt:.1f}s, Scan={scan_dt:.1f}s")

                return image_result, statistics

            finally:
                _stderr("  🧹 Очистка...")
                await self.remove_docker_image(image_name)

    async def scan_local_dockerfiles(self) -> List[Dict[str, Any]]:
        input_file = os.path.join(self.script_dir, "input_images_files.txt")
        if not os.path.exists(input_file):
            _stderr(f"❌ Файл {input_file} не найден")
            _stderr("📝 Создайте файл input_images_files.txt, пример:")
            _stderr("# severity=4\n# /path/to/Dockerfile\n")
            return []

        severity_level, dockerfiles = self.parse_input_file(input_file, "files")
        if not dockerfiles:
            _stderr("❌ Не найдено Dockerfile для сканирования")
            return []

        total = len(dockerfiles)
        _stderr(f"\n🚀 Начинаю сборку и сканирование {total} Dockerfile...")
        _stderr(f"⚙️  Параллельность (local jobs): {self.jobs_local}")
        _stderr(f"📁 Trivy cache-dir: {self.cache_dir}")

        ok_db, msg_db = await self.ensure_trivy_databases()
        if not ok_db:
            _stderr(f"❌ Не удалось подготовить Trivy DB: {msg_db}")
            _stderr("💡 Быстрый фикс руками: trivy clean --vuln-db --java-db  (или rm -rf .trivy_cache/db .trivy_cache/java-db)")
            return []

        sem = asyncio.Semaphore(self.jobs_local)
        tasks = [self._scan_one_local(i + 1, total, dockerfiles[i], severity_level, sem) for i in range(total)]
        pairs = await asyncio.gather(*tasks)

        results: List[Dict[str, Any]] = []
        overall_statistics: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for image_result, stats in pairs:
            results.append(image_result)
            for comp_type, sev_map in stats.items():
                for sev, count in sev_map.items():
                    overall_statistics[comp_type][sev] += count

        if overall_statistics:
            _stderr(self.generate_summary_report(overall_statistics))
        return results

    # ------------------------- SAVE -------------------------

    def save_results(self, results: List[Dict[str, Any]], output_file: str) -> bool:
        # Компактный JSON: быстрее писать и меньше размер
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, separators=(",", ":"))
            return True
        except Exception as e:
            _stderr(f"❌ Ошибка сохранения {output_file}: {e}")
            return False

    # ------------------------- RUN -------------------------

    async def run_async(self) -> int:
        mode = self.mode or self.show_menu()

        if mode == "remote":
            results_all = await self.scan_remote_images()
            scan_type = "remote"
        elif mode == "local":
            results_all = await self.scan_local_dockerfiles()
            scan_type = "local"
        elif mode == "both":
            r1 = await self.scan_remote_images()
            r2 = await self.scan_local_dockerfiles()
            results_all = r1 + r2
            scan_type = "both"
        else:
            _stderr("❌ Неизвестный режим")
            return 2

        if not results_all:
            _stderr("❌ Нет результатов для сохранения")
            return 1

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"advanced_scan_results_{scan_type}_{timestamp}.json"
        output_path = os.path.join(self.script_dir, file_name)

        if not self.save_results(results_all, output_path):
            return 1

        # В stdout — только имя файла
        _stdout(file_name)
        return 0

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(add_help=True)
    p.add_argument("--mode", choices=["remote", "local", "both"], default=None, help="Режим работы (по умолчанию интерактивное меню)")
    p.add_argument("--jobs-remote", type=int, default=2, help="Параллельность для remote-скана (по умолчанию 2)")
    p.add_argument("--jobs-local", type=int, default=1, help="Параллельность для local (docker build + scan). По умолчанию 1")
    p.add_argument("--trivy-timeout", type=str, default=DEFAULT_TRIVY_TIMEOUT, help=f"Timeout trivy (например 10m). По умолчанию {DEFAULT_TRIVY_TIMEOUT}")
    return p.parse_args(argv)

def main() -> None:
    try:
        args = parse_args(sys.argv[1:])
        scanner = TrivyScanner(
            mode=args.mode,
            jobs_remote=args.jobs_remote,
            jobs_local=args.jobs_local,
            trivy_timeout=args.trivy_timeout,
        )
        rc = asyncio.run(scanner.run_async())
        sys.exit(rc)
    except KeyboardInterrupt:
        _stderr("\n\n👋 Выход по запросу пользователя")
        sys.exit(0)
    except Exception as e:
        _stderr(f"\n❌ Критическая ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
