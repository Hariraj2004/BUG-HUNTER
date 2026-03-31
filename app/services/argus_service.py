import uuid
import time
import re
import os
import sys
import subprocess
import threading
from typing import Dict, Any, List, Optional
from .security_analyzer import SecurityAnalyzer


ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\[\?[0-9;]*[a-zA-Z]|\r')


class ArgusService:
    def __init__(self):
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.supported_modules: Dict[int, Dict[str, Any]] = {}
        self._modules_dir: Optional[str] = None
        self._analyzer = SecurityAnalyzer()
        self._load_modules()

    def _load_modules(self):
        """Auto-load all modules from the Argus catalog."""
        try:
            from argus.core.catalog_cache import tools
            import argus
            base = os.path.dirname(os.path.abspath(argus.__file__))
            self._modules_dir = os.path.join(base, "modules")

            for t in tools:
                if t.get("script") and t.get("section") not in ("Run All Scripts", "Special Mode"):
                    mid = int(t["number"])
                    self.supported_modules[mid] = {
                        "module_id": mid,
                        "name": t["name"],
                        "section": t["section"],
                        "script": t["script"]  # e.g. "open_ports.py"
                    }
        except ImportError:
            self.supported_modules = {
                9:   {"module_id": 9,   "name": "Open Ports Scan",        "section": "Network & Infrastructure", "script": "open_ports.py"},
                104: {"module_id": 104, "name": "Security.txt Check",     "section": "Security & Threat Intelligence", "script": "security_txt.py"},
                108: {"module_id": 108, "name": "Subdomain Enumeration",  "section": "Security & Threat Intelligence", "script": "subdomain_enum.py"},
            }

    def list_modules(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return modules grouped by section."""
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for mod in sorted(self.supported_modules.values(), key=lambda m: m["module_id"]):
            sec = mod["section"]
            groups.setdefault(sec, []).append({
                "module_id": mod["module_id"],
                "name": mod["name"],
                "section": mod["section"]
            })
        return groups

    def get_module(self, module_id: int) -> Optional[Dict[str, Any]]:
        return self.supported_modules.get(module_id)

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        return self.jobs.get(job_id)

    def get_all_jobs(self) -> List[Dict[str, Any]]:
        return list(self.jobs.values())

    def start_scan(self, module_id: int, target: str) -> Dict[str, Any]:
        mod = self.supported_modules.get(module_id)
        if not mod:
            raise ValueError(f"Unsupported module ID: {module_id}")

        job_id = str(uuid.uuid4())

        job = {
            "job_id": job_id,
            "module_id": module_id,
            "module_name": mod["name"],
            "section": mod["section"],
            "target": target,
            "status": "queued",
            "created_at": int(time.time()),
            "started_at": None,
            "finished_at": None,
            "output": "",
            "parsed_result": {},
            "security_analysis": {},
            "error": None
        }

        self.jobs[job_id] = job

        worker = threading.Thread(
            target=self._run_job,
            args=(job_id,),
            daemon=True
        )
        worker.start()

        return job

    def _clean_target(self, target: str) -> str:
        """Strip protocol and trailing slashes to get a clean domain."""
        t = target.strip()
        for prefix in ("https://", "http://", "ftp://"):
            if t.lower().startswith(prefix):
                t = t[len(prefix):]
        return t.rstrip("/").split("/")[0]

    def _run_job(self, job_id: str):
        job = self.jobs[job_id]
        job["status"] = "running"
        job["started_at"] = int(time.time())

        try:
            mod = self.supported_modules[job["module_id"]]
            script_name = mod["script"]  # e.g. "open_ports.py"
            module_name = os.path.splitext(script_name)[0]  # "open_ports"
            target = self._clean_target(job["target"])

            # Run the module script directly via python -m argus.modules.<name> <target>
            # This avoids the CLI shell and the argument-passing bug
            cmd = [
                sys.executable, "-m",
                f"argus.modules.{module_name}",
                target
            ]

            # Set wide terminal so Rich tables aren't truncated
            env = os.environ.copy()
            env["COLUMNS"] = "200"

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                env=env
            )

            raw_output = proc.stdout + proc.stderr
            clean_output = ANSI_ESCAPE.sub('', raw_output)
            job["output"] = clean_output
            job["parsed_result"] = self._parse_output(clean_output)
            job["security_analysis"] = self._analyzer.analyze(
                job["parsed_result"].get("lines", []),
                job.get("module_name", "")
            )
            job["status"] = "completed"

        except subprocess.TimeoutExpired:
            job["status"] = "failed"
            job["error"] = "Scan timed out (300s limit)"
        except Exception as e:
            job["status"] = "failed"
            job["error"] = str(e)
        finally:
            job["finished_at"] = int(time.time())

    # Lines that are CLI/Rich decoration noise
    NOISE_PATTERNS = [
        r'^\s*$',
        r'^[╭╮╰╯│─━┃┏┓┗┛┣┫┳┻╋═\s]+$',
        r'^={10,}$',
        r'^\s*Argus\s*-\s*',
    ]

    def _parse_output(self, output: str) -> Dict[str, Any]:
        """Parse output, stripping decoration noise."""
        lines = [l.strip() for l in output.splitlines() if l.strip()]

        clean = []
        for line in lines:
            skip = False
            for pattern in self.NOISE_PATTERNS:
                if re.search(pattern, line):
                    skip = True
                    break
            if not skip and all(c in '╭╮╰╯│─━┃┏┓┗┛┣┫┳┻╋═ ' for c in line):
                skip = True
            if not skip:
                clean.append(line)

        return {
            "summary": f"Scan returned {len(clean)} result lines",
            "lines": clean[-100:]
        }
