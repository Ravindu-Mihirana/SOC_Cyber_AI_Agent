"""Minimal MCP client that runs a scan and prints normalized JSON."""

import argparse
import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def scan(target: str, scanner: str, scan_type: str, wordlist: str | None) -> dict[str, object]:
    # Use this interpreter so the MCP child process always uses the active venv.
    server = StdioServerParameters(command=sys.executable, args=["-m", "soc_cyber_agent.nmap_server"])
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            if scanner == "nmap":
                started = await session.call_tool("run_nmap_scan", {"target": target, "scan_type": scan_type})
                result_tool = "get_scan_results"
            elif scanner == "nikto":
                started = await session.call_tool("run_nikto_scan", {"target_url": target})
                result_tool = "get_web_scan_results"
            else:
                if not wordlist:
                    raise ValueError("Gobuster requires --wordlist PATH")
                started = await session.call_tool("run_gobuster_scan", {"target_url": target, "wordlist": wordlist})
                result_tool = "get_web_scan_results"
            payload = _tool_payload(started)
            if "job_id" not in payload:
                raise RuntimeError(payload.get("error", "Could not start scan"))
            job_id = payload["job_id"]
            while True:
                status_result = await session.call_tool("get_scan_status", {"job_id": job_id})
                status = _tool_payload(status_result)
                if status.get("status") in {"done", "failed"}:
                    break
                await asyncio.sleep(2)
            if status["status"] == "failed":
                raise RuntimeError(status.get("error") or "Scan failed")
            result = await session.call_tool(result_tool, {"job_id": job_id})
            payload = _tool_payload(result)
            if "error" in payload:
                raise RuntimeError(str(payload["error"]))
            return payload


def _tool_payload(result: object) -> dict[str, object]:
    """Read MCP structured output, falling back to its text representation."""
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    content = getattr(result, "content", None) or []
    if content and isinstance(getattr(content[0], "text", None), str):
        try:
            parsed = json.loads(content[0].text)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
    if getattr(result, "isError", False):
        raise RuntimeError("MCP tool call failed; see the MCP server output for details.")
    raise RuntimeError("MCP server returned an unrecognized response.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a scanner through the local MCP server")
    parser.add_argument("target", help="An authorized IP/hostname for Nmap or http(s) URL for web scans")
    parser.add_argument("--scanner", choices=("nmap", "nikto", "gobuster"), default="nmap")
    parser.add_argument("--scan-type", choices=("quick", "version"), default="quick")
    parser.add_argument("--wordlist", help="Existing local wordlist file required by Gobuster")
    args = parser.parse_args()
    try:
        print(json.dumps(asyncio.run(scan(args.target, args.scanner, args.scan_type, args.wordlist)), indent=2))
    except BaseExceptionGroup as exc:
        cause: BaseException = exc
        while isinstance(cause, BaseExceptionGroup) and cause.exceptions:
            cause = cause.exceptions[0]
        print(f"MCP server connection failed: {cause}", file=sys.stderr)
        raise SystemExit(1) from exc
    except Exception as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
