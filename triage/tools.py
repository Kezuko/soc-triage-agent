"""Read-only investigation tools exposed to the model via function calling.

Design rule: the model can only *read*. No tool here changes anything.
Containment actions are proposed in the structured verdict and only run after
policy checks and explicit human approval (see approval.py).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from . import data


def lookup_indicator(indicator_type: str, value: str) -> dict:
    table = {"ip": "ips", "domain": "domains", "sha256": "hashes"}.get(indicator_type)
    if table is None:
        return {"error": f"unsupported indicator_type {indicator_type!r}"}
    hit = data.intel()[table].get(value)
    return {"indicator": value, "type": indicator_type, "found": hit is not None, **(hit or {})}


def get_asset_context(hostname: str) -> dict:
    asset = data.assets().get(hostname)
    return {"hostname": hostname, "found": asset is not None, **(asset or {})}


def query_host_events(hostname: str, event_type: str) -> dict:
    events = data.logs().get(hostname, [])
    if event_type != "any":
        events = [e for e in events if e.get("event") == event_type]
    return {"hostname": hostname, "event_type": event_type, "count": len(events), "events": events[:25]}


TOOL_FUNCTIONS: dict[str, Callable[..., dict]] = {
    "lookup_indicator": lookup_indicator,
    "get_asset_context": get_asset_context,
    "query_host_events": query_host_events,
}

TOOL_SPECS: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "lookup_indicator",
        "description": "Look up reputation for an IP, domain or SHA256 in threat intelligence.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "indicator_type": {"type": "string", "enum": ["ip", "domain", "sha256"]},
                "value": {"type": "string"},
            },
            "required": ["indicator_type", "value"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "get_asset_context",
        "description": "Get owner, criticality and role for a hostname from the asset inventory.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {"hostname": {"type": "string"}},
            "required": ["hostname"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "query_host_events",
        "description": "Retrieve endpoint/auth/network events recorded for a host.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string"},
                "event_type": {
                    "type": "string",
                    "enum": [
                        "any", "process_start", "dns_query", "network_connect", "file_create",
                        "registry_set", "auth_failure", "auth_success", "vpn_login",
                    ],
                },
            },
            "required": ["hostname", "event_type"],
            "additionalProperties": False,
        },
    },
]


def call_tool(name: str, arguments_json: str) -> dict:
    fn = TOOL_FUNCTIONS.get(name)
    if fn is None:
        return {"error": f"unknown tool {name!r}"}
    try:
        args = json.loads(arguments_json or "{}")
        return fn(**args)
    except (TypeError, ValueError) as exc:
        return {"error": f"bad arguments for {name}: {exc}"}
