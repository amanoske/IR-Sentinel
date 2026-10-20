import json
import os
import sys
from datetime import timedelta

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@pytest.mark.asyncio
async def test_real_stdio_file_investigation(tmp_path):
    source = tmp_path / "attached.txt"
    source.write_text("This harmless attachment remains in place.")
    environment = {key: os.environ[key] for key in ("XDG_CONFIG_HOME", "XDG_STATE_HOME")}
    parameters = StdioServerParameters(
        command=sys.executable, args=["-m", "ir_sentinel.server"], env=environment
    )
    async with stdio_client(parameters) as (reader, writer):
        async with ClientSession(
            reader, writer, read_timeout_seconds=timedelta(seconds=20)
        ) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {t.name for t in tools.tools} >= {
                "investigate_evidence",
                "correlate_otx",
                "generate_defense",
                "validate_defense",
            }
            result = await session.call_tool("investigate_evidence", {"path": str(source)})
            assert not result.isError
            case_id = result.structuredContent["case_id"]
            page = await session.call_tool("read_evidence", {"case_id": case_id})
            assert not page.isError
            data = page.structuredContent or json.loads(page.content[0].text)
            assert data["records"][0]["ref"] == "file:metadata"
            invalid = await session.call_tool("read_evidence", {"case_id": "../../etc/passwd"})
            assert invalid.isError
    assert source.read_text() == "This harmless attachment remains in place."
