"""Recto signs; whoever asked sends. The chain modules and the phone's chain services sign on every chain Recto supports, and
none of them reaches the network: Recto never broadcasts a transaction, reads a balance or calls a chain node. These tests
turn red when a chain module, a module it imports from this package, or a file of the phone's chain part gains a network
library, a dynamic import, a subprocess or a network API."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "recto"

CHAIN_MODULES = ["bitcoin", "ethereum", "solana", "stellar", "ripple", "tron"]

# A top-level module a signer has no use for: the network, or a way round this scan.
FORBIDDEN_MODULES = {
    "aiohttp", "asyncio", "ftplib", "grpc", "http", "httpx", "imaplib", "importlib", "poplib", "requests", "selectors",
    "smtplib", "socket", "socketserver", "ssl", "subprocess", "telnetlib", "urllib", "urllib3", "web3", "websocket",
    "websockets", "xmlrpc",
}
FORBIDDEN_NAMES = {"__import__", "urlopen", "create_connection", "system", "popen"}

PHONE = REPO / "phone" / "Recto"
PHONE_CHAIN_FILES = [
    "Recto/Services/MauiBtcSignService.cs",
    "Recto/Services/MauiEd25519ChainSignService.cs",
    "Recto/Services/MauiEthSignService.cs",
    "Recto/Services/MauiTronSignService.cs",
    "Recto.Shared/Services/IBtcSignService.cs",
    "Recto.Shared/Services/IEd25519ChainSignService.cs",
    "Recto.Shared/Services/IEthSignService.cs",
    "Recto.Shared/Services/ITronSignService.cs",
    "Recto.Shared/Services/BtcSigningOps.cs",
    "Recto.Shared/Services/Ed25519ChainSigningOps.cs",
    "Recto.Shared/Services/EthSigningOps.cs",
    "Recto.Shared/Services/TronSigningOps.cs",
    "Recto.Shared/Services/Bip32.cs",
    "Recto.Shared/Services/Bip39.cs",
    "Recto.Shared/Services/Slip10.cs",
]

# A .NET network API, an RPC client, or an address to call; read with the comments removed, since the comments name the
# methods a consumer calls with the signed bytes.
FORBIDDEN_CS = [
    r"\bHttpClient\b", r"\bIHttpClientFactory\b", r"\bHttpRequestMessage\b", r"\bHttpMessageHandler\b",
    r"\bWebSocket\b", r"\bClientWebSocket\b", r"\bSocket\b", r"\bTcpClient\b", r"\bUdpClient\b", r"\bWebRequest\b",
    r"\bWebClient\b", r"\bSystem\.Net\b", r"\bWeb3\b", r"\bRpcClient\b", r"\bJsonRpc\w*\b", r"://",
]


def _imports(tree: ast.AST) -> set[str]:
    """Every module a source imports, nested imports included, with a relative import's dots kept."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            found.add("." * node.level + (node.module or ""))
    return found


def _names(tree: ast.AST) -> set[str]:
    """Every bare name and attribute a source uses."""
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}


def _package_module(name: str) -> str | None:
    """The module of this package an import names, or None for an outside one."""
    if name.startswith("recto."):
        return name.split(".")[1]
    if name.startswith("."):
        return name.lstrip(".").split(".")[0] or None
    return None


def _chain_closure() -> list[str]:
    """The chain modules and every module of this package they import, transitively."""
    seen: list[str] = []
    todo = list(CHAIN_MODULES)
    while todo:
        name = todo.pop(0)
        if name in seen:
            continue
        seen.append(name)
        source = PACKAGE / f"{name}.py"
        assert source.is_file(), f"recto/{name}.py is gone: a chain module was renamed or moved - update this test"
        for imported in _imports(ast.parse(source.read_text(encoding="utf-8"))):
            inner = _package_module(imported)
            if inner and inner not in seen:
                todo.append(inner)
    return seen


@pytest.mark.parametrize("name", _chain_closure())
def test_a_chain_module_imports_no_network(name: str) -> None:
    tree = ast.parse((PACKAGE / f"{name}.py").read_text(encoding="utf-8"))
    reached = sorted(m for m in _imports(tree) if m.split(".")[0] in FORBIDDEN_MODULES)
    assert not reached, f"recto/{name}.py imports {reached}: Recto signs, whoever asked sends"


@pytest.mark.parametrize("name", _chain_closure())
def test_a_chain_module_calls_no_way_round(name: str) -> None:
    tree = ast.parse((PACKAGE / f"{name}.py").read_text(encoding="utf-8"))
    reached = sorted(_names(tree) & FORBIDDEN_NAMES)
    assert not reached, f"recto/{name}.py uses {reached}: Recto signs, whoever asked sends"


def test_the_closure_is_the_chain_modules() -> None:
    # A chain module that starts importing another part of the package widens what this test reads; name it here on purpose.
    assert sorted(_chain_closure()) == sorted(CHAIN_MODULES)


def _strip_cs_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)
    return re.sub(r"//[^\n]*", " ", source)


@pytest.mark.parametrize("path", PHONE_CHAIN_FILES)
def test_the_phones_chain_part_reaches_no_network(path: str) -> None:
    source = PHONE / path
    assert source.is_file(), f"phone/Recto/{path} is gone: a chain file was renamed or moved - update this test"
    code = _strip_cs_comments(source.read_text(encoding="utf-8"))
    reached = sorted({p for p in FORBIDDEN_CS if re.search(p, code)})
    assert not reached, f"phone/Recto/{path} names {reached}: Recto signs, whoever asked sends"


def test_the_scan_sees_what_it_forbids() -> None:
    # The scans' own falsifiers: each would turn red on the thing it guards.
    planted = ast.parse("import socket\nfrom urllib.request import urlopen\nurlopen('x')\n__import__('requests')\nos.system('x')\n")
    assert {"socket", "urllib.request"} <= {m for m in _imports(planted) if m.split(".")[0] in FORBIDDEN_MODULES}
    assert {"__import__", "urlopen", "system"} <= _names(planted) & FORBIDDEN_NAMES
    code = _strip_cs_comments("// a consumer calls eth_sendRawTransaction at https://node\nvar c = new HttpClient();\n")
    assert [p for p in FORBIDDEN_CS if re.search(p, code)] == [r"\bHttpClient\b"]
