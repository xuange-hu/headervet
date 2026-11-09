"""Entrypoint surface: MCP manifest must match the real tool registration."""

from __future__ import annotations

import asyncio
import os
import sys

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

import headervet  # noqa: E402
import headervet.mcp_server as ms  # noqa: E402


def test_version_is_importable():
    assert headervet.__version__ == "0.1.0"


def test_manifest_matches_tools_tuple():
    names = {t["name"] for t in ms.tool_manifest()}
    assert names == set(ms.TOOLS)


def test_every_tool_has_a_nonempty_description():
    for tool in ms.tool_manifest():
        assert len(tool["description"]) > 30, tool["name"]


def test_every_public_tool_is_documented_and_callable():
    for name in ms.TOOLS:
        fn = getattr(ms, name, None)
        assert callable(fn), name
        assert fn.__doc__, f"{name} lacks a docstring (it becomes the MCP description)"


def test_mcp_import_is_deferred_into_build_server():
    path = os.path.join(SRC, "headervet", "mcp_server.py")
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    import_line = source.index("from mcp.server.fastmcp import FastMCP")
    function_line = source.index("def build_server")
    assert function_line < import_line


def test_build_server_registers_exactly_the_documented_tools():
    pytest.importorskip("mcp", reason="the `mcp` optional extra is not installed")
    mcp = ms.build_server()
    tools = asyncio.run(mcp.list_tools())
    assert {t.name for t in tools} == set(ms.TOOLS)
    for t in tools:
        assert t.description, t.name


def test_tool_signatures_use_simple_json_types():
    pytest.importorskip("mcp", reason="the `mcp` optional extra is not installed")
    mcp = ms.build_server()
    tools = asyncio.run(mcp.list_tools())
    for t in tools:
        for prop in t.inputSchema.get("properties", {}).values():
            assert prop.get("type") in ("string", "boolean", "integer", "number"), (
                t.name,
                prop,
            )
