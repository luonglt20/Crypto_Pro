from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import ClassVar

from .models import Finding, Location
from .rules import RULES


class Provenance(StrEnum):
    UNKNOWN = "unknown"
    LITERAL = "literal"
    CONSTANT = "constant"
    SECURE_RANDOM = "secure_random"
    WEAK_RANDOM = "weak_random"
    TIME_DERIVED = "time_derived"
    COUNTER = "counter"
    EXTERNAL = "external"
    DERIVED = "derived"


@dataclass(frozen=True)
class AbstractValue:
    provenance: Provenance
    byte_length: int | None = None
    origin: str | None = None


UNKNOWN = AbstractValue(Provenance.UNKNOWN)


@dataclass
class ObjectState:
    api: str
    key: AbstractValue
    nonce: AbstractValue = UNKNOWN
    line: int = 1
    decrypted_line: int | None = None
    verified: bool = False


class CryptoAnalyzer:
    version = "0.1.0"

    KEY_CONSTRUCTORS: ClassVar[set[str]] = {
        "cryptography.hazmat.primitives.ciphers.aead.AESGCM",
        "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305",
        "AESGCM",
        "ChaCha20Poly1305",
    }
    SECURE_RANDOM_APIS: ClassVar[set[str]] = {
        "os.urandom",
        "secrets.token_bytes",
        "cryptography.hazmat.primitives.ciphers.aead.AESGCM.generate_key",
        "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305.generate_key",
        "AESGCM.generate_key",
        "ChaCha20Poly1305.generate_key",
        "Crypto.Random.get_random_bytes",
        "get_random_bytes",
    }
    WEAK_RANDOM_PREFIXES: ClassVar[tuple[str, ...]] = ("random.", "numpy.random.")
    TIME_APIS: ClassVar[set[str]] = {"time.time", "time.time_ns", "datetime.datetime.now"}

    def analyze(self, source: str, path: str, scan_id: str) -> list[Finding]:
        tree = ast.parse(source, filename=path)
        aliases = self._aliases(tree)
        state = _AnalysisState(path, scan_id, aliases)
        self._walk_statements(tree.body, state, in_loop=False, module_level=True)
        state.finish()
        return state.findings

    def _aliases(self, tree: ast.AST) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split(".")[0]] = item.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for item in node.names:
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        return aliases

    def _walk_statements(
        self,
        statements: Iterable[ast.stmt],
        state: _AnalysisState,
        *,
        in_loop: bool,
        module_level: bool,
    ) -> None:
        for node in statements:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                child = state.child_scope()
                for arg in node.args.args:
                    child.values[arg.arg] = AbstractValue(Provenance.EXTERNAL, origin="argument")
                self._walk_statements(node.body, child, in_loop=False, module_level=False)
                child.finish()
                state.merge_findings(child)
                continue
            if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                self._walk_statements(node.body, state, in_loop=True, module_level=False)
                self._walk_statements(node.orelse, state, in_loop=in_loop, module_level=False)
                continue
            if isinstance(node, ast.If):
                self._walk_statements(node.body, state, in_loop=in_loop, module_level=False)
                self._walk_statements(node.orelse, state, in_loop=in_loop, module_level=False)
                continue
            if isinstance(node, ast.Try):
                self._check_invalid_tag_handler(node, state)
                self._walk_statements(node.body, state, in_loop=in_loop, module_level=False)
                for handler in node.handlers:
                    self._walk_statements(handler.body, state, in_loop=in_loop, module_level=False)
                self._walk_statements(node.orelse, state, in_loop=in_loop, module_level=False)
                self._walk_statements(node.finalbody, state, in_loop=in_loop, module_level=False)
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                value_node = node.value
                if value_node is None:
                    continue
                value = self._eval(value_node, state)
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        state.values[target.id] = value
                        state.assignment_loop[target.id] = in_loop
                        if (
                            module_level
                            and self._looks_like_key(target.id)
                            and value.provenance != Provenance.SECURE_RANDOM
                        ):
                            state.report(
                                "KN006",
                                node,
                                {"reason_codes": ["MODULE_LEVEL_KEY"], "name": target.id},
                            )
                        if isinstance(value_node, ast.Call):
                            self._track_object(target.id, value_node, state)
                self._inspect_expr(value_node, state, in_loop=in_loop)
                continue
            if isinstance(node, ast.Expr):
                self._inspect_expr(node.value, state, in_loop=in_loop)
            else:
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, ast.expr):
                        self._inspect_expr(child, state, in_loop=in_loop)

    def _track_object(self, name: str, call: ast.Call, state: _AnalysisState) -> None:
        api = state.qualname(call.func)
        if self._is_key_constructor(api) and call.args:
            state.objects[name] = ObjectState(
                api=api, key=self._eval(call.args[0], state), line=call.lineno
            )
        elif api.endswith("AES.new") and call.args:
            nonce_node = self._keyword(call, "nonce")
            state.objects[name] = ObjectState(
                api=api,
                key=self._eval(call.args[0], state),
                nonce=self._eval(nonce_node, state) if nonce_node else UNKNOWN,
                line=call.lineno,
            )

    def _inspect_expr(self, expr: ast.expr, state: _AnalysisState, *, in_loop: bool) -> None:
        for node in ast.walk(expr):
            if not isinstance(node, ast.Call):
                continue
            api = state.qualname(node.func)
            if self._is_key_constructor(api) and node.args:
                self._check_key(node.args[0], node, api, state)
            elif api.endswith("AES.new") and node.args:
                self._check_key(node.args[0], node, api, state)
                nonce_node = self._keyword(node, "nonce") or self._positional(node, 2)
                if nonce_node:
                    self._check_nonce(nonce_node, node, api, state, in_loop=in_loop)

            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                obj = state.objects.get(node.func.value.id)
                if obj:
                    method = node.func.attr
                    if method == "encrypt" and node.args:
                        self._check_nonce(
                            node.args[0], node, f"{obj.api}.encrypt", state, in_loop=in_loop
                        )
                        state.record_key_purpose(node.func.value.id, "encryption", obj.key, node)
                    elif method == "decrypt":
                        obj.decrypted_line = node.lineno
                    elif method in {"verify", "decrypt_and_verify"}:
                        obj.verified = True
                    elif method == "sign":
                        state.record_key_purpose(node.func.value.id, "signing", obj.key, node)

            # High-level AEAD APIs are commonly used as a one-shot chain, for example
            # AESGCM(key).encrypt(nonce, data, aad), without assigning the object first.
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
                constructor = node.func.value
                constructor_api = state.qualname(constructor.func)
                if (
                    self._is_key_constructor(constructor_api)
                    and constructor.args
                    and node.func.attr == "encrypt"
                    and node.args
                ):
                    self._check_nonce(
                        node.args[0],
                        node,
                        f"{constructor_api}.encrypt",
                        state,
                        in_loop=in_loop,
                    )

            if api.endswith((".sign", ".DSS.new")):
                k_node = self._keyword(node, "k") or self._keyword(node, "randfunc")
                if k_node:
                    value = self._eval(k_node, state)
                    if value.provenance in {
                        Provenance.LITERAL,
                        Provenance.CONSTANT,
                        Provenance.WEAK_RANDOM,
                        Provenance.TIME_DERIVED,
                    }:
                        state.report(
                            "KN007",
                            node,
                            {
                                "api": api,
                                "source_kind": value.provenance.value,
                                "reason_codes": ["SIGNATURE_NONCE_UNSAFE"],
                            },
                        )

    def _check_key(
        self, value_node: ast.expr, node: ast.AST, api: str, state: _AnalysisState
    ) -> None:
        value = self._eval(value_node, state)
        if value.provenance in {Provenance.LITERAL, Provenance.CONSTANT}:
            state.report(
                "KN001",
                node,
                {
                    "api": api,
                    "source_kind": value.provenance.value,
                    "reason_codes": ["KEY_STATIC_VALUE"],
                },
            )
        elif value.provenance in {Provenance.WEAK_RANDOM, Provenance.TIME_DERIVED}:
            state.report(
                "KN002",
                node,
                {
                    "api": api,
                    "source_kind": value.provenance.value,
                    "reason_codes": ["KEY_WEAK_SOURCE"],
                },
            )

    def _check_nonce(
        self,
        value_node: ast.expr,
        node: ast.AST,
        api: str,
        state: _AnalysisState,
        *,
        in_loop: bool,
    ) -> None:
        value = self._eval(value_node, state)
        reason: list[str] = []
        if value.provenance in {Provenance.LITERAL, Provenance.CONSTANT}:
            reason.append("NONCE_CONSTANT")
        if (
            isinstance(value_node, ast.Name)
            and in_loop
            and not state.assignment_loop.get(value_node.id, False)
        ):
            reason.append("NONCE_LOOP_INVARIANT")
        if reason:
            state.report(
                "KN003",
                node,
                {"api": api, "source_kind": value.provenance.value, "reason_codes": reason},
            )
        elif value.provenance in {Provenance.WEAK_RANDOM, Provenance.TIME_DERIVED}:
            state.report(
                "KN002",
                node,
                {
                    "api": api,
                    "source_kind": value.provenance.value,
                    "reason_codes": ["NONCE_WEAK_SOURCE"],
                },
            )
        required = 12 if "AESGCM" in api or "ChaCha20Poly1305" in api else None
        if required and value.byte_length is not None and value.byte_length != required:
            state.report(
                "KN008",
                node,
                {
                    "api": api,
                    "observed_length": value.byte_length,
                    "required_length": required,
                    "reason_codes": ["NONCE_LENGTH"],
                },
            )

    def _check_invalid_tag_handler(self, node: ast.Try, state: _AnalysisState) -> None:
        for handler in node.handlers:
            if handler.type is None:
                continue
            name = state.qualname(handler.type)
            if name.endswith(("InvalidTag", "ValueError")):
                fail_closed = any(isinstance(x, (ast.Raise, ast.Return)) for x in ast.walk(handler))
                if not fail_closed:
                    state.report(
                        "KN005",
                        handler,
                        {"exception": name, "reason_codes": ["AUTH_FAILURE_CONTINUES"]},
                    )

    def _eval(self, node: ast.expr | None, state: _AnalysisState) -> AbstractValue:
        if node is None:
            return UNKNOWN
        if isinstance(node, ast.Constant):
            length = len(node.value) if isinstance(node.value, (bytes, str)) else None
            return AbstractValue(Provenance.LITERAL, length, "literal")
        if isinstance(node, ast.Name):
            value = state.values.get(node.id, UNKNOWN)
            if value.provenance == Provenance.LITERAL:
                return AbstractValue(Provenance.CONSTANT, value.byte_length, node.id)
            return value
        if isinstance(node, ast.Call):
            api = state.qualname(node.func)
            if api in self.SECURE_RANDOM_APIS or api.endswith((".generate_key", ".token_bytes")):
                return AbstractValue(Provenance.SECURE_RANDOM, self._requested_length(node), api)
            if api.startswith(self.WEAK_RANDOM_PREFIXES) or api in {"random", "random.randbytes"}:
                return AbstractValue(Provenance.WEAK_RANDOM, self._requested_length(node), api)
            if api in self.TIME_APIS:
                return AbstractValue(Provenance.TIME_DERIVED, None, api)
            if api in {"bytes", "bytearray"} and node.args:
                size = self._constant_int(node.args[0])
                return AbstractValue(Provenance.LITERAL, size, api)
            return AbstractValue(Provenance.DERIVED, None, api)
        if isinstance(node, ast.BinOp):
            left, right = self._eval(node.left, state), self._eval(node.right, state)
            weak = {Provenance.WEAK_RANDOM, Provenance.TIME_DERIVED}
            if left.provenance in weak or right.provenance in weak:
                return AbstractValue(Provenance.WEAK_RANDOM, origin="expression")
            if left.provenance in {
                Provenance.LITERAL,
                Provenance.CONSTANT,
            } and right.provenance in {Provenance.LITERAL, Provenance.CONSTANT}:
                length = None
                if (
                    isinstance(node.op, ast.Add)
                    and left.byte_length is not None
                    and right.byte_length is not None
                ):
                    length = left.byte_length + right.byte_length
                if isinstance(node.op, ast.Mult):
                    if left.byte_length is not None:
                        length = left.byte_length * (self._constant_int(node.right) or 0)
                    elif right.byte_length is not None:
                        length = right.byte_length * (self._constant_int(node.left) or 0)
                return AbstractValue(Provenance.CONSTANT, length, "constant_expression")
        return UNKNOWN

    @staticmethod
    def _constant_int(node: ast.expr) -> int | None:
        return (
            node.value if isinstance(node, ast.Constant) and isinstance(node.value, int) else None
        )

    def _requested_length(self, call: ast.Call) -> int | None:
        if call.args:
            return self._constant_int(call.args[0])
        for key in ("nbytes", "length"):
            value = self._keyword(call, key)
            if value:
                return self._constant_int(value)
        return None

    @staticmethod
    def _keyword(call: ast.Call, name: str) -> ast.expr | None:
        return next((kw.value for kw in call.keywords if kw.arg == name), None)

    @staticmethod
    def _positional(call: ast.Call, index: int) -> ast.expr | None:
        return call.args[index] if len(call.args) > index else None

    @staticmethod
    def _looks_like_key(name: str) -> bool:
        lowered = name.lower()
        return lowered in {"key", "secret_key", "encryption_key", "signing_key"}

    def _is_key_constructor(self, api: str) -> bool:
        return api in self.KEY_CONSTRUCTORS or api.endswith((".AESGCM", ".ChaCha20Poly1305"))


class _AnalysisState:
    def __init__(self, path: str, scan_id: str, aliases: dict[str, str]) -> None:
        self.path = PurePosixPath(path).as_posix()
        self.scan_id = scan_id
        self.aliases = aliases
        self.values: dict[str, AbstractValue] = {}
        self.assignment_loop: dict[str, bool] = {}
        self.objects: dict[str, ObjectState] = {}
        self.key_purposes: dict[str, set[str]] = {}
        self.findings: list[Finding] = []
        self._dedupe: set[tuple[str, int, str]] = set()

    def child_scope(self) -> _AnalysisState:
        child = _AnalysisState(self.path, self.scan_id, self.aliases)
        child.values.update(self.values)
        return child

    def merge_findings(self, child: _AnalysisState) -> None:
        for finding in child.findings:
            key = (finding.rule_id, finding.location.line, str(finding.evidence))
            if key not in self._dedupe:
                self._dedupe.add(key)
                self.findings.append(finding)

    def qualname(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.qualname(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Tuple):
            return ".".join(self.qualname(x) for x in node.elts)
        return ""

    def report(self, rule_id: str, node: ast.AST, evidence: dict[str, object]) -> None:
        line = getattr(node, "lineno", 1)
        key = (rule_id, line, repr(sorted(evidence.items())))
        if key in self._dedupe:
            return
        self._dedupe.add(key)
        rule = RULES[rule_id]
        self.findings.append(
            Finding(
                scan_id=self.scan_id,
                rule_id=rule.rule_id,
                category=rule.category,
                cwe_id=rule.cwe_id,
                severity=rule.severity,
                confidence=rule.confidence,
                status=rule.default_status,
                location=Location(path=self.path, line=line, column=getattr(node, "col_offset", 0)),
                evidence=evidence,
                recommendation=rule.recommendation,
            )
        )

    def record_key_purpose(
        self, name: str, purpose: str, key: AbstractValue, node: ast.AST
    ) -> None:
        identity = key.origin or name
        purposes = self.key_purposes.setdefault(identity, set())
        purposes.add(purpose)
        if len(purposes) > 1:
            self.report(
                "KN006",
                node,
                {
                    "key_identity": identity,
                    "purposes": sorted(purposes),
                    "reason_codes": ["KEY_MULTI_PURPOSE"],
                },
            )

    def finish(self) -> None:
        for name, obj in self.objects.items():
            if obj.decrypted_line is not None and not obj.verified and obj.api.endswith("AES.new"):
                fake = ast.Pass(lineno=obj.decrypted_line, col_offset=0)
                self.report(
                    "KN005",
                    fake,
                    {"object": name, "api": obj.api, "reason_codes": ["DECRYPT_WITHOUT_VERIFY"]},
                )


def digest_source(source: str) -> str:
    return "sha256:" + hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()
