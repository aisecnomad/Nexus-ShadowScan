"""network.logs: AI services contacted, from DNS, TLS SNI and flow logs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.network import logs as network_logs
from shadowscan.connectors.network.logs import NetworkLogConnector, _address, _host, _int, _ip, _zeek_escape
from shadowscan.models import Kind, ScanStats, Surface
from shadowscan.signatures import get_index

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "network"


def scan(run_connector, path: Path, **config):
    findings, ctx = run_connector("network.logs", input=str(path), label="hq", **config)
    by = {(f.metadata["client"], f.metadata["service"]): f for f in findings}
    assert len(by) == len(findings)
    return by, ctx.stats


def test_zeek_dns_ssl_and_conn_logs(run_connector):
    found, stats = scan(run_connector, FIXTURES / "zeek")
    assert not stats.errors and not stats.incomplete
    assert stats.warnings == [
        "network.logs: 1 flow(s) with ambiguous service attribution were not attributed"
    ]
    assert set(found) == {
        ("10.1.4.21", "provider.anthropic"),
        ("10.1.4.21", "provider.openai"),
        ("10.1.4.33", "identity-app.openai-chatgpt"),
        ("10.1.4.40", "protocol.mcp"),
        ("10.1.4.70", "provider.ollama"),
        ("10.1.4.80", "coding-agent.cursor"),
    }

    anthropic = found[("10.1.4.21", "provider.anthropic")]
    assert anthropic.surface == Surface.NETWORK and anthropic.kind == Kind.NETWORK_CONTACT
    assert anthropic.title == "AI service contacted: Anthropic (api.anthropic.com) from 10.1.4.21"
    assert anthropic.resource == "network:hq:10.1.4.21:provider.anthropic" and anthropic.account == "hq"
    assert (anthropic.metadata["dns_queries"], anthropic.metadata["tls_connections"]) == (1, 5)
    assert anthropic.metadata["flows"] == 5 and anthropic.metadata["bytes_out"] == 90010
    assert "agent-loop" in anthropic.tags and anthropic.model_providers == ["provider.anthropic"]
    assert anthropic.first_seen == "2025-09-29T08:00:00+00:00"

    # Resolved, but its address is shared with a non-AI host: the flow is not attributed.
    openai = found[("10.1.4.21", "provider.openai")]
    assert openai.metadata["flows"] == 0 and openai.metadata["ambiguous_flows_in_input"] == 1

    chatgpt = found[("10.1.4.33", "identity-app.openai-chatgpt")]
    assert chatgpt.metadata["flows"] == 1 and "agent-service" not in chatgpt.tags
    # Another client's DNS answers cannot identify this client's traffic.
    assert ("10.1.4.60", "identity-app.openai-chatgpt") not in found

    for key in [("10.1.4.40", "protocol.mcp"), ("10.1.4.80", "coding-agent.cursor")]:
        assert "agent-service" in found[key].tags and found[key].metadata["agent_indicators"] == 1
    assert found[("10.1.4.70", "provider.ollama")].metadata["hosts"] == {"10.9.0.5:11434": 2}
    assert not any(client in {"10.1.4.50"} for client, _ in found)


def test_route53_resolver_and_vpc_flow_logs(run_connector):
    found, stats = scan(run_connector, FIXTURES / "aws")
    assert not stats.warnings and not stats.incomplete
    assert set(found) == {("10.20.1.15", "provider.aws-bedrock"), ("10.20.1.15", "cloud.aws-bedrock-agents")}
    runtime = found[("10.20.1.15", "provider.aws-bedrock")]
    # The historical Route 53 export has no TTLs: retain observed queries,
    # but do not invent a validity interval or infer execution cadence.
    assert runtime.metadata["flows"] == runtime.metadata["bytes_out"] == 0
    assert "agent-loop" not in runtime.tags
    assert any("without timestamp or TTL" in item for item in runtime.metadata["limitations"])
    agents = found[("10.20.1.15", "cloud.aws-bedrock-agents")]
    assert "agent-service" in agents.tags and "agent-loop" not in agents.tags


def test_generic_dns_csv_keeps_only_ai_hosts(run_connector):
    found, stats = scan(run_connector, FIXTURES / "generic_dns.csv")
    assert not stats.warnings
    assert set(found) == {
        ("192.168.5.20", "provider.google-gemini"),
        ("192.168.5.20", "provider.openrouter"),
    }


def test_zeek_json_and_generic_json_documents(run_connector, tmp_path):
    lines = [
        {"_path": "dns", "ts": 1759132800.5, "uid": "D1", "id.orig_h": "10.0.0.9", "query": "api.openai.com",
         "answers": ["162.159.140.245"]},
        {"_path": "ssl", "ts": 1759132801.0, "uid": "C1", "id.orig_h": "10.0.0.9", "id.resp_h": "162.159.140.245",
         "id.resp_p": 443, "server_name": "api.openai.com"},
        {"_path": "conn", "ts": 1759132801.0, "uid": "C1", "id.orig_h": "10.0.0.9",
         "id.resp_h": "162.159.140.245", "id.resp_p": 443, "orig_bytes": 1000, "resp_bytes": 50},
        {"_path": "ssl", "ts": 1759132802.0, "id.orig_h": "10.0.0.9", "id.resp_h": "1.1.1.1"},
    ]  # fmt: skip
    (tmp_path / "zeek.json").write_text("\n".join(json.dumps(line) for line in lines) + "\n")
    (tmp_path / "sni.json").write_text(
        json.dumps(
            {
                "records": [
                    {"client_ip": "10.0.0.10", "sni": "API.Anthropic.com.", "ts": "2025-09-29T08:00:00Z"}
                ]
            }
        )
    )
    found, stats = scan(run_connector, tmp_path)
    assert not stats.warnings
    openai = found[("10.0.0.9", "provider.openai")]
    assert (openai.metadata["dns_queries"], openai.metadata["tls_connections"], openai.metadata["flows"]) == (
        1,
        1,
        1,
    )
    assert found[("10.0.0.10", "provider.anthropic")].metadata["hosts"] == {"api.anthropic.com": 1}


@pytest.mark.parametrize(
    ("name", "content", "message"),
    [
        ("bad.log", "#separator \\x09\n#fields\tts\tquery\n1\ta\tb\n", "malformed Zeek line 3"),
        ("bad.log", "hello world\n", "unrecognized line 1"),
        ("bad.jsonl", '{"query": "api.openai.com"\n', "invalid JSON at line 1"),
        ("bad.json", "[1]", "records must be objects"),
        ("bad.json", '"text"', "unrecognized JSON document"),
        ("bad.json", '[{"query": "api.openai.com"}]', "DNS record without a client address"),
        ("bad.json", '[{"_path": "ssl", "server_name": "api.openai.com"}]', "TLS record without a client"),
        ("bad.json", '[{"_path": "http", "id.orig_h": "10.0.0.1"}]', "no query, server name or flow"),
        ("bad.json", '[{"color": "blue"}]', "unrecognized record"),
        ("bad.log", "version srcaddr dstaddr dstport action log-status\n2 x 10.0.0.2 443 ACCEPT OK\n",
         "malformed VPC flow record"),
        ("empty.log", "\n", "empty log"),
    ],
)  # fmt: skip
def test_malformed_input_makes_the_scan_incomplete(run_connector, tmp_path, name, content, message):
    path = tmp_path / name
    path.write_text(content)
    _, stats = scan(run_connector, path)
    assert stats.incomplete
    assert any(message in m for m in stats.warnings + stats.errors), stats.warnings + stats.errors


@pytest.mark.parametrize("content", ["", "\n\n"])
def test_empty_json_exports_are_errors(run_connector, tmp_path, content):
    for name in ("empty.json", "empty.jsonl"):
        (tmp_path / name).write_text(content)
    _, stats = scan(run_connector, tmp_path)
    assert stats.incomplete and stats.errors


def test_global_dns_attribution_is_refused_for_shared_addresses(run_connector, tmp_path):
    rows = [
        {"client": "10.0.0.1", "query": "api.openai.com", "answers": ["203.0.113.5"]},
        {"client": "10.0.0.2", "query": "cdn.example.net", "answers": ["203.0.113.5"]},
        {"client": "10.0.0.3", "dst_ip": "203.0.113.5", "dst_port": 443, "bytes": 10},
        {"client": "10.0.0.3", "dst_ip": "198.51.100.1", "dst_port": 443, "bytes": 10},
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert set(found) == {("10.0.0.1", "provider.openai")}
    assert not stats.incomplete and not stats.warnings


def test_format_option_and_record_limit(run_connector, tmp_path):
    path = tmp_path / "rows.jsonl"
    path.write_text(
        "".join(json.dumps({"client": f"10.0.0.{i}", "query": "api.openai.com"}) + "\n" for i in range(5))
    )
    found, stats = scan(run_connector, path, format="generic", max_records=3)
    assert len(found) == 3 and stats.incomplete
    assert any("max_records" in w for w in stats.warnings)


def test_vpc_flows_with_the_default_format_and_no_header(run_connector, tmp_path):
    (tmp_path / "dns.jsonl").write_text(
        json.dumps(
            {
                "client": "10.0.0.4",
                "query": "api.mistral.ai",
                "answers": ["198.51.100.9"],
                "ts": 1759132799,
                "ttl": 60,
            }
        )
        + "\n"
    )
    (tmp_path / "flows.log").write_text(
        "2 1 eni-1 10.0.0.4 198.51.100.9 40000 443 6 3 1200 1759132800 1759132860 ACCEPT OK\n"
    )
    found, stats = scan(run_connector, tmp_path)
    assert not stats.warnings
    assert found[("10.0.0.4", "provider.mistral")].metadata["flows"] == 1


@pytest.mark.parametrize("suffix", ["log", "json"])
@pytest.mark.parametrize("status", ["SKIPDATA", "UNKNOWN", "-"])
def test_vpc_missing_capture_or_unknown_status_fails_cli_closed(tmp_path, suffix, status):
    path = tmp_path / f"flow.{suffix}"
    if suffix == "log":
        # AWS's default v2 layout uses '-' for the missing flow fields.
        path.write_text(
            f"2 123456789010 eni-11111111aaaaaaaaa - - - - - - - 1431280876 1431280934 - {status}\n"
        )
    else:
        path.write_text(json.dumps({"srcaddr": "-", "dstaddr": "-", "log-status": status}))
    result = CliRunner().invoke(main, ["run", "network.logs", "--input", str(path), "--format", "json"])
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    assert report["findings"] == []
    message = "SKIPDATA reports uncaptured flows" if status == "SKIPDATA" else "invalid VPC flow log-status"
    assert message in result.output


@pytest.mark.parametrize("suffix", ["log", "json"])
def test_vpc_nodata_remains_a_complete_empty_cli_result(tmp_path, suffix):
    path = tmp_path / f"flow.{suffix}"
    if suffix == "log":
        path.write_text("2 123456789010 eni-11111111aaaaaaaaa - - - - - - - 1431280876 1431280934 - NODATA\n")
    else:
        path.write_text(json.dumps({"log_status": "NODATA"}))
    result = CliRunner().invoke(main, ["run", "network.logs", "--input", str(path), "--format", "json"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is True
    assert report["findings"] == []


@pytest.mark.parametrize("status", [None, False, 0, "", " ", [], {}, ["OK"], "untrusted-status-value"])
@pytest.mark.parametrize("field", ["log-status", "log_status"])
def test_vpc_explicit_invalid_status_cannot_fall_back_to_ok(run_connector, tmp_path, field, status):
    rows = [
        {"client": "10.0.0.1", "query": "api.openai.com", "answers": ["203.0.113.5"]},
        {"srcaddr": "10.0.0.1", "dstaddr": "203.0.113.5", "dstport": 443, "bytes": 100, field: status},
    ]
    path = tmp_path / "flow.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert stats.incomplete and any("invalid VPC flow log-status" in w for w in stats.warnings)
    assert all("untrusted-status-value" not in w for w in stats.warnings)
    assert found[("10.0.0.1", "provider.openai")].metadata["flows"] == 0


@pytest.mark.parametrize(
    "statuses", [{"log-status": "OK", "log_status": "SKIPDATA"}, {"log_status": "SKIPDATA"}]
)
def test_vpc_status_only_json_fails_closed_without_flow_endpoints(tmp_path, statuses):
    path = tmp_path / "flow.json"
    path.write_text(json.dumps(statuses))
    result = CliRunner().invoke(main, ["run", "network.logs", "--input", str(path), "--format", "json"])
    assert result.exit_code == 3, result.output
    assert json.loads(result.stdout)["summary"]["complete"] is False


@pytest.mark.parametrize("statuses", [{}, {"log-status": "OK", "log_status": "ok"}])
def test_vpc_optional_or_matching_statuses_preserve_normal_flows(run_connector, tmp_path, statuses):
    rows = [
        {"client": "10.0.0.1", "query": "api.openai.com", "answers": ["203.0.113.5"], "ts": 1000, "ttl": 60},
        {
            "srcaddr": "10.0.0.1",
            "dstaddr": "203.0.113.5",
            "dstport": 443,
            "bytes": 100,
            "start": 1001,
            **statuses,
        },
    ]
    path = tmp_path / "flow.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete and not stats.warnings
    assert found[("10.0.0.1", "provider.openai")].metadata["bytes_out"] == 100


def test_caps_on_clients_and_pairs(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_CLIENTS", 2)
    monkeypatch.setattr(network_logs, "_MAX_PAIRS", 1)
    rows = [{"client": f"10.0.0.{i}", "query": "api.openai.com"} for i in range(3)]
    rows += [{"client": "10.0.0.0", "dst_ip": f"198.51.100.{i}", "dst_port": 443} for i in range(2)]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert len(found) == 2 and stats.incomplete
    assert any("beyond the first 2" in w for w in stats.warnings)
    assert any("beyond 1 connection groups" in w for w in stats.warnings)


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("offset", range(7))
def test_uid_attribution_is_connection_scoped_and_order_independent(run_connector, tmp_path, reverse, offset):
    rows = json.loads((FIXTURES / "shared_ip.json").read_text())
    rows = rows[offset:] + rows[:offset]
    if reverse:
        rows.reverse()
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete and not stats.warnings
    assert set(found) == {("10.0.0.1", "provider.openai"), ("10.0.0.1", "provider.anthropic")}
    for service, sent, received, first in [
        ("provider.openai", 100, 50, "2025-09-29T08:00:00+00:00"),
        ("provider.anthropic", 200, 70, "2025-09-29T08:00:10+00:00"),
    ]:
        finding = found[("10.0.0.1", service)]
        assert finding.metadata["flows"] == 1
        assert finding.metadata["bytes_out"] == sent
        assert finding.metadata["bytes_in"] == received
        assert finding.first_seen == finding.last_seen == first
        assert "agent-loop" not in finding.tags


@pytest.mark.parametrize("uid", [None, "", "-", "different-connection"])
def test_missing_or_unmatched_uid_does_not_inherit_another_connections_sni(run_connector, tmp_path, uid):
    rows = [
        {
            "client": "10.0.0.1",
            "dst_ip": "203.0.113.5",
            "dst_port": 443,
            "uid": "C1",
            "sni": "api.openai.com",
        },
        {"client": "10.0.0.1", "dst_ip": "203.0.113.5", "dst_port": 443, "uid": uid, "bytes_out": 1000000},
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete and not stats.warnings
    finding = found[("10.0.0.1", "provider.openai")]
    assert finding.metadata["flows"] == finding.metadata["bytes_out"] == 0


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("conflict", ["non-ai", "other-ai", "server", "port"])
def test_conflicting_uid_evidence_blocks_dns_fallback(run_connector, tmp_path, reverse, conflict):
    tls = {
        "client": "10.0.0.1",
        "dst_ip": "203.0.113.5",
        "dst_port": 443,
        "uid": "C1",
        "sni": "api.openai.com",
    }
    other = dict(tls)
    other.update(
        {
            "non-ai": {"sni": "cdn.example.net"},
            "other-ai": {"sni": "api.anthropic.com"},
            "server": {"dst_ip": "203.0.113.6"},
            "port": {"dst_port": 8443},
        }[conflict]
    )
    rows = [
        {"client": "10.0.0.1", "query": "api.openai.com", "answers": ["203.0.113.5"]},
        tls,
        {"client": "10.0.0.1", "dst_ip": "203.0.113.5", "dst_port": 443, "uid": "C1", "bytes_out": 100},
        other,
    ]
    if reverse:
        rows.reverse()
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete
    assert stats.warnings == [
        "network.logs: 1 flow(s) with ambiguous service attribution were not attributed"
    ]
    assert all(f.metadata["flows"] == f.metadata["bytes_out"] == 0 for f in found.values())


@pytest.mark.parametrize("reverse", [False, True])
def test_uid_reuse_across_clients_does_not_transfer_traffic(run_connector, tmp_path, reverse):
    rows = [
        {
            "client": "10.0.0.1",
            "dst_ip": "203.0.113.5",
            "dst_port": 443,
            "uid": "C1",
            "sni": "api.openai.com",
        },
        {"client": "10.0.0.1", "dst_ip": "203.0.113.5", "dst_port": 443, "uid": "C1", "bytes_out": 100},
        {
            "client": "10.0.0.2",
            "dst_ip": "203.0.113.5",
            "dst_port": 443,
            "uid": "C1",
            "sni": "api.anthropic.com",
        },
        {"client": "10.0.0.2", "dst_ip": "203.0.113.5", "dst_port": 443, "uid": "C1", "bytes_out": 200},
        {"client": "10.0.0.3", "dst_ip": "203.0.113.5", "dst_port": 443, "uid": "C1", "bytes_out": 1000000},
    ]
    if reverse:
        rows.reverse()
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete and not stats.warnings
    assert set(found) == {("10.0.0.1", "provider.openai"), ("10.0.0.2", "provider.anthropic")}
    assert found[("10.0.0.1", "provider.openai")].metadata["bytes_out"] == 100
    assert found[("10.0.0.2", "provider.anthropic")].metadata["bytes_out"] == 200


@pytest.mark.parametrize("endpoint", [{"dst_ip": "203.0.113.6"}, {"dst_port": 8443}])
def test_flow_endpoint_mismatch_does_not_fall_back_to_dns(run_connector, tmp_path, endpoint):
    rows = [
        {"client": "10.0.0.1", "query": "api.openai.com", "answers": ["203.0.113.5", "203.0.113.6"]},
        {
            "client": "10.0.0.1",
            "dst_ip": "203.0.113.5",
            "dst_port": 443,
            "uid": "C1",
            "sni": "api.openai.com",
        },
        {
            "client": "10.0.0.1",
            "dst_ip": "203.0.113.5",
            "dst_port": 443,
            "uid": "C1",
            "bytes_out": 100,
            **endpoint,
        },
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete and any("ambiguous service attribution" in w for w in stats.warnings)
    assert found[("10.0.0.1", "provider.openai")].metadata["flows"] == 0


def test_connection_group_cap_counts_distinct_uids_on_one_address(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_PAIRS", 1)
    rows = [
        {"client": "10.0.0.1", "query": "api.openai.com", "answers": ["203.0.113.5"], "ts": 1000, "ttl": 60}
    ]
    rows += [
        {
            "client": "10.0.0.1",
            "dst_ip": "203.0.113.5",
            "dst_port": 443,
            "uid": uid,
            "bytes_out": 100,
            "ts": 1001,
        }
        for uid in ["C1", "C2", "C1"]
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert stats.incomplete and any(
        "1 flow record(s) beyond 1 connection groups" in w for w in stats.warnings
    )
    finding = found[("10.0.0.1", "provider.openai")]
    assert finding.metadata["flows"] == 2 and finding.metadata["bytes_out"] == 200


def test_tls_identity_cap_does_not_allow_dns_to_override_dropped_non_ai_sni(
    run_connector, tmp_path, monkeypatch
):
    monkeypatch.setattr(network_logs, "_MAX_PAIRS", 1)
    rows = [
        {"client": "10.0.0.1", "query": "api.openai.com", "answers": ["203.0.113.5"]},
        {"client": "10.0.0.1", "uid": "C1", "sni": "api.openai.com"},
        {"client": "10.0.0.1", "uid": "C2", "sni": "cdn.example.net"},
        {"client": "10.0.0.1", "uid": "C2", "dst_ip": "203.0.113.5", "dst_port": 443, "bytes_out": 1000000},
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert stats.incomplete and any(
        "TLS record(s) beyond 1 client/UID identities" in w for w in stats.warnings
    )
    assert found[("10.0.0.1", "provider.openai")].metadata["bytes_out"] == 0


@pytest.mark.parametrize("reverse", [False, True])
def test_uid_with_multiple_flow_endpoints_is_ambiguous_without_tls_endpoints(
    run_connector, tmp_path, reverse
):
    rows = [
        {"client": "10.0.0.1", "uid": "C1", "sni": "api.openai.com"},
        {"client": "10.0.0.1", "uid": "C1", "dst_ip": "203.0.113.5", "dst_port": 443, "bytes_out": 100},
        {"client": "10.0.0.1", "uid": "C1", "dst_ip": "203.0.113.6", "dst_port": 443, "bytes_out": 1000000},
    ]
    if reverse:
        rows.reverse()
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete
    assert stats.warnings == [
        "network.logs: 2 flow(s) with ambiguous service attribution were not attributed"
    ]
    assert found[("10.0.0.1", "provider.openai")].metadata["bytes_out"] == 0


def test_uid_links_tls_without_optional_endpoints_to_one_connection(run_connector, tmp_path):
    rows = [
        {"client": "10.0.0.1", "uid": "C1", "sni": "api.openai.com"},
        {"client": "10.0.0.1", "uid": "C1", "dst_ip": "203.0.113.5", "dst_port": 443, "bytes_out": 100},
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete and not stats.warnings
    assert found[("10.0.0.1", "provider.openai")].metadata["bytes_out"] == 100


def test_zeek_missing_uid_marker_is_not_a_connection_identifier(run_connector, tmp_path):
    rows = [
        {"client": "10.0.0.1", "uid": "-", "sni": "api.openai.com"},
        {"client": "10.0.0.1", "uid": "-", "dst_ip": "203.0.113.5", "dst_port": 443, "bytes_out": 1000000},
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete and not stats.warnings
    assert found[("10.0.0.1", "provider.openai")].metadata["bytes_out"] == 0


def test_non_ai_tls_does_not_become_ollama_traffic_from_port(run_connector, tmp_path):
    rows = [
        {"client": "10.0.0.1", "uid": "C1", "sni": "cdn.example.net"},
        {"client": "10.0.0.1", "uid": "C1", "dst_ip": "203.0.113.5", "dst_port": 11434, "bytes_out": 100},
    ]
    path = tmp_path / "rows.json"
    path.write_text(json.dumps(rows))
    found, stats = scan(run_connector, path)
    assert not stats.incomplete and not stats.warnings and not found


def test_configuration_and_live_mode_are_refused(run_connector):
    with pytest.raises(ConnectorError):
        NetworkLogConnector(ConnectorContext(config={"format": "pcap"}, index=get_index()))
    _, ctx = run_connector("network.logs")
    assert ctx.stats.skipped and ctx.stats.incomplete


@pytest.mark.parametrize(
    ("value", "expected"),
    [("API.OpenAI.com.", "api.openai.com"), ("10.0.0.1", None), ("not a host", None), ("", None), ({}, None)],
)
def test_host_normalisation(value, expected):
    assert _host(value) == expected


def test_small_helpers():
    assert _zeek_escape("\\x09") == "\t"
    assert (_int("12"), _int(True), _int("-1"), _int("x")) == (12, None, None, None)
    # Address literals are canonical (an IPv6 client's resource id is case- and zero-insensitive).
    assert (_address("2001:0DB8:0:0:0:0:0:1"), _address("010.0.0.1"), _address(None)) == (
        "2001:db8::1",
        "010.0.0.1",
        "None",
    )
    assert (_ip("::FFFF:10.0.0.1"), _ip("10.0.0.1"), _ip("10.0.0"), _ip({})) == (True, True, False, False)


def _scan_network_rows(run_connector, tmp_path, rows, **config):
    path = tmp_path / "observations.json"
    path.write_text(json.dumps(rows))
    return scan(run_connector, path, **config)


def _temporal_rows(*, flow_time=1001, ttl=60):
    return [
        {
            "client": "192.0.2.10",
            "query": "api.openai.com",
            "answers": ["203.0.113.8"],
            "ts": 1000,
            "TTLs": [ttl],
        },
        {"client": "192.0.2.10", "dst_ip": "203.0.113.8", "dst_port": 443, "ts": flow_time, "bytes_out": 100},
    ]


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("offset", range(6))
def test_temporal_dns_fixture_attributes_only_fresh_same_client_context(
    run_connector, tmp_path, reverse, offset
):
    rows = json.loads((FIXTURES / "temporal_dns.json").read_text())
    rows = rows[offset:] + rows[:offset]
    if reverse:
        rows.reverse()
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete and not stats.warnings
    assert set(found) == {("192.0.2.10", "provider.openai")}
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.metadata["flows"] == 1 and finding.metadata["bytes_out"] == 100
    assert finding.metadata["dns_attribution"] == [
        {
            "host": "api.openai.com",
            "address": "203.0.113.8",
            "observed_at": "1970-01-01T00:16:40+00:00",
            "refreshed_at": "1970-01-01T00:16:40+00:00",
            "expires_at": "1970-01-01T00:17:40+00:00",
            "ttl_seconds": 60,
            "flow_at": "1970-01-01T00:16:41+00:00",
            "sensor": "sensor-a",
            "network_id": "",
            "resolver": "",
        }
    ]


@pytest.mark.parametrize(
    ("flow_time", "ttl", "expected"),
    [
        (999, 60, 0),
        (1000, 60, 1),
        (1059.9, 60, 1),
        (1060, 60, 0),
        (2000000, 60, 0),
        (1000, 0, 0),
    ],
)
def test_dns_ttl_window_is_half_open_and_never_explains_future_answers(
    run_connector, tmp_path, flow_time, ttl, expected
):
    found, stats = _scan_network_rows(run_connector, tmp_path, _temporal_rows(flow_time=flow_time, ttl=ttl))
    assert not stats.incomplete
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == expected


@pytest.mark.parametrize("missing", ["dns-ts", "ttl", "flow-ts"])
def test_missing_dns_validity_metadata_preserves_queries_not_flow_attribution(
    run_connector, tmp_path, missing
):
    rows = _temporal_rows()
    if missing == "dns-ts":
        del rows[0]["ts"]
    elif missing == "ttl":
        del rows[0]["TTLs"]
    else:
        del rows[1]["ts"]
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.metadata["dns_queries"] == 1 and finding.metadata["flows"] == 0
    if missing != "flow-ts":
        assert (
            "DNS observations without timestamp or TTL cannot attribute flows"
            in finding.metadata["limitations"]
        )


@pytest.mark.parametrize("ttl", [True, -1, "nan", "inf", {}, "invalid", 2**32])
def test_malformed_dns_ttl_is_incomplete_without_flow_attribution(run_connector, tmp_path, ttl):
    found, stats = _scan_network_rows(run_connector, tmp_path, _temporal_rows(ttl=ttl))
    assert stats.incomplete and any("malformed DNS TTL" in warning for warning in stats.warnings)
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


def test_invalid_dns_timestamp_and_answer_limit_fail_closed(run_connector, tmp_path):
    rows = _temporal_rows()
    rows[0].update(ts="bad timestamp", answers=[f"203.0.113.{i}" for i in range(33)], TTLs=[60] * 33)
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete
    assert any("invalid DNS timestamp" in warning for warning in stats.warnings)
    assert any("DNS answer limit" in warning for warning in stats.warnings)
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


@pytest.mark.parametrize("field", ["sensor", "network_id", "resolver"])
@pytest.mark.parametrize("other", ["other", None])
def test_dns_attribution_requires_exact_supplied_context(run_connector, tmp_path, field, other):
    rows = _temporal_rows()
    rows[0][field] = "one"
    if other is not None:
        rows[1][field] = other
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


def test_dns_cname_chain_uses_shortest_ttl_and_ipv6_normalization(run_connector, tmp_path):
    rows = _temporal_rows(flow_time=1005)
    rows[0].update(answers=["edge.example.net", "2001:db8::1"], TTLs=[10, 600])
    rows[1]["dst_ip"] = "2001:0db8:0:0:0:0:0:1"
    rows.append({**rows[1], "ts": 1010, "bytes_out": 999})
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete
    assert found[("192.0.2.10", "provider.openai")].metadata["bytes_out"] == 100


@pytest.mark.parametrize("negative_ttl", [60, None])
def test_shared_address_conflict_including_unknown_validity_blocks_dns(run_connector, tmp_path, negative_ttl):
    rows = _temporal_rows()
    other = {**rows[0], "query": "cdn.example.net"}
    if negative_ttl is None:
        del other["TTLs"]
    rows.append(other)
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete
    assert any("ambiguous service attribution" in warning for warning in stats.warnings)
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


def test_ip_reuse_after_expiry_does_not_link_previous_provider(run_connector, tmp_path):
    rows = _temporal_rows(flow_time=1101)
    rows.append({**rows[0], "query": "api.anthropic.com", "ts": 1100})
    found, stats = _scan_network_rows(run_connector, tmp_path, list(reversed(rows)))
    assert not stats.incomplete and not stats.warnings
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0
    assert found[("192.0.2.10", "provider.anthropic")].metadata["flows"] == 1


@pytest.mark.parametrize("limit", ["_MAX_DNS_OBSERVATIONS", "_MAX_DNS_PER_ADDRESS"])
def test_dns_budget_exhaustion_disables_fallback_even_when_conflict_dropped(
    run_connector, tmp_path, monkeypatch, limit
):
    monkeypatch.setattr(network_logs, limit, 1)
    rows = _temporal_rows()
    rows.append({**rows[0], "query": "cdn.example.net"})
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete and any("DNS observation(s) exceeded" in warning for warning in stats.warnings)
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


def test_duplicate_dns_observation_does_not_consume_budget(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_DNS_OBSERVATIONS", 1)
    rows = _temporal_rows()
    rows.append(dict(rows[0]))
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 1


def test_dns_expiry_skew_and_maximum_age_are_explicit_and_bounded(run_connector, tmp_path):
    found, _ = _scan_network_rows(
        run_connector, tmp_path, _temporal_rows(flow_time=1061), dns_clock_skew_seconds=2
    )
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 1
    found, _ = _scan_network_rows(
        run_connector, tmp_path, _temporal_rows(flow_time=999), dns_clock_skew_seconds=2
    )
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0
    found, _ = _scan_network_rows(
        run_connector, tmp_path, _temporal_rows(flow_time=1010), dns_max_ttl_seconds=10
    )
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


@pytest.mark.parametrize(
    "config",
    [
        {"dns_clock_skew_seconds": -1},
        {"dns_clock_skew_seconds": 61},
        {"dns_clock_skew_seconds": True},
        {"dns_clock_skew_seconds": "1"},
        {"dns_max_ttl_seconds": 604801},
        {"dns_max_ttl_seconds": 0},
    ],
)
def test_dns_options_reject_invalid_values(config):
    with pytest.raises(ConnectorError):
        NetworkLogConnector(ConnectorContext(config=config, index=get_index()))


@pytest.mark.parametrize("suffix", ["jsonl", "log"])
def test_ja4_json_and_zeek_tsv_are_non_scoring_and_collision_safe(run_connector, suffix):
    found, stats = scan(run_connector, FIXTURES / f"ja4_ssl.{suffix}")
    assert not stats.incomplete and not stats.warnings
    assert set(found) == {("192.0.2.10", "provider.openai")}
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.confidence == 0.7 and finding.kind == Kind.NETWORK_CONTACT
    assert len(finding.evidence) == 1 and finding.evidence[0].signal == "network:tls-sni"
    assert finding.metadata["tls_fingerprints"] == [
        {
            "type": "ja4",
            "value": "t13d1516h2_8daaf6152771_02713d6af862",
            "source_field": "ja4",
            "sensor": "",
            "network_id": "",
            "resolver": "",
            "uid": "C1",
        }
    ]


@pytest.mark.parametrize("fingerprint", ["invalid", "x" * 10000, {}, 5])
def test_malformed_ja4_is_incomplete_but_does_not_discard_sni(run_connector, tmp_path, fingerprint):
    rows = [{"client": "192.0.2.10", "sni": "api.openai.com", "ja4": fingerprint}]
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete and any("invalid or conflicting JA4" in warning for warning in stats.warnings)
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.confidence == 0.7 and "tls_fingerprints" not in finding.metadata


def test_ja4_alias_duplicate_and_conflicting_uid_do_not_transfer_fingerprints(run_connector, tmp_path):
    rows = [json.loads((FIXTURES / "ja4_ssl.jsonl").read_text().splitlines()[0])]
    rows[0]["tls.ja4"] = rows[0].pop("ja4")
    rows.append(dict(rows[0]))
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete
    fingerprints = found[("192.0.2.10", "provider.openai")].metadata["tls_fingerprints"]
    assert len(fingerprints) == 1 and fingerprints[0]["source_field"] == "tls.ja4"
    rows.append({**rows[0], "server_name": "docs.example.net"})
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert "tls_fingerprints" not in found[("192.0.2.10", "provider.openai")].metadata


def test_ja4_storage_is_bounded_and_context_uid_join_is_scoped(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_JA4_PER_CONTACT", 1)
    row = json.loads((FIXTURES / "ja4_ssl.jsonl").read_text().splitlines()[0])
    rows = [dict(row), {**row, "uid": "C2"}]
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete and any("JA4 observation(s) exceeded" in warning for warning in stats.warnings)
    assert "tls_fingerprints" not in found[("192.0.2.10", "provider.openai")].metadata
    rows = [{**row, "sensor": "one"}, {**row, "server_name": "docs.example.net", "sensor": "two"}]
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete
    assert len(found[("192.0.2.10", "provider.openai")].metadata["tls_fingerprints"]) == 1


def test_network_enrichment_never_resolves_names(run_connector, monkeypatch):
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("offline network logs must not resolve names")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket, "gethostbyname_ex", refuse)
    found, stats = scan(run_connector, FIXTURES / "temporal_dns.json")
    assert not stats.incomplete and found


@pytest.mark.parametrize("prefix", ["ts3i000000", "dd2i0304h1", "q13d1516h3", "t00d1516X2"])
def test_ja4_supports_upstream_version_and_alpn_tokens(run_connector, tmp_path, prefix):
    fingerprint = prefix + "_000000000000_000000000000"
    found, stats = _scan_network_rows(
        run_connector, tmp_path, [{"client": "192.0.2.10", "sni": "api.openai.com", "ja4": fingerprint}]
    )
    assert not stats.incomplete
    assert found[("192.0.2.10", "provider.openai")].metadata["tls_fingerprints"][0]["value"] == fingerprint


@pytest.mark.parametrize("mode", ["aliases", "uid"])
def test_conflicting_ja4_values_are_incomplete_and_not_attached(run_connector, tmp_path, mode):
    row = json.loads((FIXTURES / "ja4_ssl.jsonl").read_text().splitlines()[0])
    other = "t13d1516h2_000000000000_000000000000"
    rows = [{**row, "tls.ja4": other}] if mode == "aliases" else [row, {**row, "ja4": other}]
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete and any("conflicting JA4" in warning for warning in stats.warnings)
    assert "tls_fingerprints" not in found[("192.0.2.10", "provider.openai")].metadata


@pytest.mark.parametrize("context", [123, {}, "x" * 256, "one\ntwo"])
def test_malformed_context_cannot_collapse_into_default_scope(run_connector, tmp_path, context):
    rows = _temporal_rows()
    rows[1]["sensor"] = context
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete and any("malformed observation context" in warning for warning in stats.warnings)
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


@pytest.mark.parametrize("kind", ["flow", "vpc", "tls"])
def test_invalid_event_timestamp_is_reported(run_connector, tmp_path, kind):
    row = {
        "flow": {"client": "192.0.2.10", "dst_ip": "203.0.113.8", "ts": "invalid"},
        "vpc": {"srcaddr": "192.0.2.10", "dstaddr": "203.0.113.8", "dstport": 443, "start": "invalid"},
        "tls": {"client": "192.0.2.10", "sni": "api.openai.com", "ts": "invalid"},
    }[kind]
    _, stats = _scan_network_rows(run_connector, tmp_path, [row])
    assert stats.incomplete and any("invalid event timestamp" in warning for warning in stats.warnings)


def test_fresh_dns_cannot_override_non_ai_sni_or_cross_sensor_uid(run_connector, tmp_path):
    rows = _temporal_rows()
    rows[1]["uid"] = "C1"
    rows.append({"client": "192.0.2.10", "uid": "C1", "sni": "docs.example.net"})
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0
    # A known AI SNI from another sensor must not override local non-AI DNS.
    rows[0]["query"] = "docs.example.net"
    rows[-1].update(sni="api.openai.com", sensor="another-sensor")
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


def test_dns_provenance_sample_is_bounded_and_disclosed(run_connector, tmp_path):
    rows = _temporal_rows()
    rows.extend({**rows[1], "ts": 1002 + index} for index in range(24))
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    finding = found[("192.0.2.10", "provider.openai")]
    assert not stats.incomplete and finding.metadata["flows"] == 25
    assert len(finding.metadata["dns_attribution"]) == 20
    assert "DNS attribution provenance is sampled to 20 entries" in finding.metadata["limitations"]


def test_connection_bound_counts_endpoints_not_flow_timestamps(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_PAIRS", 1)
    rows = _temporal_rows()
    rows.extend({**rows[1], "ts": 1002 + index} for index in range(2))
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete and not stats.warnings
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.metadata["flows"] == 3 and finding.metadata["bytes_out"] == 300
    assert {item["flow_at"] for item in finding.metadata["dns_attribution"]} == {
        "1970-01-01T00:16:41+00:00",
        "1970-01-01T00:16:42+00:00",
        "1970-01-01T00:16:43+00:00",
    }


def test_timestamps_per_connection_are_bounded_and_reported(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_TIMESTAMPS_PER_CONNECTION", 2)
    rows = _temporal_rows()
    rows.extend({**rows[1], "ts": 1002 + index} for index in range(2))
    rows.append(dict(rows[1]))  # repeats a kept timestamp: merged, not a new group
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete
    assert any("1 flow record(s) beyond 2 timestamps on one connection" in w for w in stats.warnings)
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.metadata["flows"] == 3 and finding.metadata["bytes_out"] == 300


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("limit", ["_MAX_DNS_OBSERVATIONS", "_MAX_DNS_PER_ADDRESS"])
def test_repeated_answers_extend_one_window_instead_of_filling_storage(
    run_connector, tmp_path, monkeypatch, limit, reverse
):
    monkeypatch.setattr(network_logs, limit, 1)
    rows = _temporal_rows(flow_time=1209)
    # Each answer arrives before the previous one expires: one window 1000..1210.
    rows.extend({**rows[0], "ts": ts} for ts in (1050, 1100, 1150))
    rows.extend({**rows[1], "ts": ts} for ts in (1001, 1120, 1210))
    if reverse:
        rows.reverse()
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete and not stats.warnings
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.metadata["flows"] == 3 and finding.metadata["dns_queries"] == 4
    windows = {
        (item["observed_at"], item["refreshed_at"], item["ttl_seconds"])
        for item in finding.metadata["dns_attribution"]
    }
    assert windows == {("1970-01-01T00:16:40+00:00", "1970-01-01T00:19:10+00:00", 60)}


@pytest.mark.parametrize("reverse", [False, True])
def test_answers_separated_by_expiry_keep_separate_windows(run_connector, tmp_path, reverse):
    # Windows 1000..1060 and 1100..1160: the flow at 1070 falls in the gap.
    rows = _temporal_rows(flow_time=1070)
    answer = rows[0]
    rows.append({**answer, "ts": 1100})
    rows.append({**rows[1], "ts": 1101})
    if reverse:
        rows.reverse()
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete and not stats.warnings
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.metadata["flows"] == 1
    assert [item["flow_at"] for item in finding.metadata["dns_attribution"]] == ["1970-01-01T00:18:21+00:00"]
    # An answer observed at 1050 overlaps both windows and bridges them.
    rows.append({**answer, "ts": 1050})
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.metadata["flows"] == 2
    assert {(item["observed_at"], item["refreshed_at"]) for item in finding.metadata["dns_attribution"]} == {
        ("1970-01-01T00:16:40+00:00", "1970-01-01T00:18:20+00:00")
    }


def test_answers_with_decremented_ttls_share_one_window(run_connector, tmp_path, monkeypatch):
    # A caching resolver reports the remaining TTL: 60 at 1000, then 30 at 1040.
    monkeypatch.setattr(network_logs, "_MAX_DNS_PER_ADDRESS", 1)
    rows = _temporal_rows(flow_time=1065)
    rows.append({**rows[0], "ts": 1040, "TTLs": [30]})
    rows.append({**rows[1], "ts": 1070})
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete and not stats.warnings
    finding = found[("192.0.2.10", "provider.openai")]
    assert finding.metadata["flows"] == 1
    assert finding.metadata["dns_attribution"] == [
        {
            "host": "api.openai.com",
            "address": "203.0.113.8",
            "observed_at": "1970-01-01T00:16:40+00:00",
            "refreshed_at": "1970-01-01T00:17:20+00:00",
            "expires_at": "1970-01-01T00:17:50+00:00",
            "ttl_seconds": 60,
            "flow_at": "1970-01-01T00:17:45+00:00",
            "sensor": "",
            "network_id": "",
            "resolver": "",
        }
    ]


@pytest.mark.parametrize(
    "defect",
    [
        {"TTLs": ["bad"]},
        {"ts": "bad timestamp"},
        {"answers": [f"203.0.113.{i}" for i in range(33)], "TTLs": [60] * 33},
        {"_path": "dns", "query": "not a host"},
    ],
)
def test_malformed_dns_record_scopes_lost_attribution_to_its_client(run_connector, tmp_path, defect):
    rows = _temporal_rows()
    rows.extend({**row, "client": "192.0.2.11"} for row in _temporal_rows())
    rows.append({**rows[0], "client": "192.0.2.11", "query": "api.anthropic.com", **defect})
    # TLS evidence is not contradicted by a DNS defect: the UID-linked flow stays attributed.
    rows.append({"client": "192.0.2.11", "uid": "C1", "sni": "api.openai.com", "ts": 1001})
    rows.append({"client": "192.0.2.11", "uid": "C1", "dst_ip": "203.0.113.8", "dst_port": 443, "ts": 1001,
                 "bytes_out": 7})  # fmt: skip
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete
    assert any("malformed or incomplete DNS records from 1 client(s)" in w for w in stats.warnings)
    clean = found[("192.0.2.10", "provider.openai")]
    assert clean.metadata["flows"] == 1 and "limitations" not in clean.metadata
    affected = found[("192.0.2.11", "provider.openai")]
    assert affected.metadata["flows"] == 1 and affected.metadata["bytes_out"] == 7
    assert (
        "DNS and service-port attribution disabled because this client's DNS records were malformed or incomplete"
        in affected.metadata["limitations"]
    )


def test_dns_defect_storage_bound_falls_back_to_the_input_wide_gate(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_CLIENTS", 1)
    rows = _temporal_rows()
    rows.extend({**rows[0], "sensor": sensor, "TTLs": ["bad"]} for sensor in ("one", "two"))
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    finding = found[("192.0.2.10", "provider.openai")]
    assert stats.incomplete and finding.metadata["flows"] == 0
    assert "Flow attribution disabled because input was incomplete" in finding.metadata["limitations"]


def test_day_long_log_attributes_within_bounds(monkeypatch):
    # 100 clients re-resolve an AI host every 60 s at a 60 s TTL for 200 minutes
    # and open a flow every two minutes for a day. Only the connection bound
    # is lowered, to the number of connections: it must count endpoints, not
    # timestamps, and 200 repeated answers must stay one window per client.
    monkeypatch.setattr(network_logs, "_MAX_PAIRS", 100)
    base, context = 1_759_000_000.0, ("", "", "")

    def records():
        for index in range(100):
            client = f"10.0.{index // 256}.{index % 256}"
            for step in range(200):
                yield {"kind": "dns", "ts": base + 60 * step, "client": client, "query": "api.openai.com",
                       "answers": ["203.0.113.8"], "ttl": 60.0, "context": context}  # fmt: skip
            for step in range(720):
                yield {"kind": "flow", "ts": base + 120 * step + 1, "client": client, "server": "203.0.113.8",
                       "port": 443, "bytes_out": 100, "bytes_in": 0, "uid": None, "context": context}  # fmt: skip

    ctx = ConnectorContext(config={"input": "unused", "label": "hq"}, index=get_index())
    connector = NetworkLogConnector(ctx)
    ctx.stats = ScanStats(connector="network.logs", started_at="now")
    findings = list(connector.analyze(records()))
    assert not ctx.stats.incomplete and not ctx.stats.warnings
    assert len(findings) == 100
    for finding in findings:
        # The window closes 60 s after the last answer: flows at 1, 121, ... 11881 s are inside.
        assert finding.metadata["flows"] == 100 and finding.metadata["dns_queries"] == 200
        assert finding.metadata["dns_attribution"][0]["refreshed_at"] == "2025-09-27T22:25:40+00:00"
        assert "DNS attribution provenance is sampled to 20 entries" in finding.metadata["limitations"]


def test_per_address_dns_bound_is_scoped_to_that_address(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_DNS_PER_ADDRESS", 1)
    rows = _temporal_rows()
    rows.append({**rows[0], "query": "cdn.example.net"})
    rows.append({**rows[0], "query": "api.anthropic.com", "answers": ["203.0.113.9"]})
    rows.append({**rows[1], "dst_ip": "203.0.113.9"})
    rows.extend({**row, "client": "192.0.2.11"} for row in _temporal_rows())
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete
    assert stats.warnings == [
        "network.logs: 1 DNS observation(s) exceeded the 1 per-address bound; DNS and service-port flow "
        "attribution disabled for 1 address(es) because discarded answers may conflict"
    ]
    openai = found[("192.0.2.10", "provider.openai")]
    assert openai.metadata["flows"] == 0
    assert any("answers exceeded storage bounds" in item for item in openai.metadata["limitations"])
    assert found[("192.0.2.10", "provider.anthropic")].metadata["flows"] == 1
    assert found[("192.0.2.11", "provider.openai")].metadata["flows"] == 1


def test_record_limit_cannot_hide_a_contradictory_dns_answer(run_connector, tmp_path):
    rows = _temporal_rows()
    rows.append({**rows[0], "query": "docs.example.net"})
    found, stats = _scan_network_rows(run_connector, tmp_path, rows, max_records=2)
    finding = found[("192.0.2.10", "provider.openai")]
    assert stats.incomplete and finding.metadata["flows"] == 0
    assert "Flow attribution disabled because input was incomplete" in finding.metadata["limitations"]


def test_truncated_input_preserves_direct_tls_context_with_limitations(run_connector, tmp_path):
    row = json.loads((FIXTURES / "ja4_ssl.jsonl").read_text().splitlines()[0])
    rows = [row, {**row, "ja4": "invalid"}]
    found, stats = _scan_network_rows(run_connector, tmp_path, rows, max_records=1)
    assert stats.incomplete
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


@pytest.mark.parametrize(
    ("first", "alias"), [("sensor", "sensor_id"), ("network_id", "vpc_id"), ("resolver", "resolver_id")]
)
def test_conflicting_context_aliases_cannot_be_used_for_attribution(run_connector, tmp_path, first, alias):
    rows = _temporal_rows()
    rows[0].update({first: "one", alias: "another"})
    rows[1][first] = "one"
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete and not found
    assert any("malformed observation context" in warning for warning in stats.warnings)


@pytest.mark.parametrize("ttls", ["60", [60]])
def test_plural_ttl_aliases_require_one_value_per_answer(run_connector, tmp_path, ttls):
    rows = _temporal_rows()
    rows[0].update(answers=["edge.example.net", "203.0.113.8"], TTLs=ttls)
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete
    assert found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


@pytest.mark.parametrize("extra", [{"ttl": 0}, {"TTL": 300}, {"ttls": [False]}])
def test_conflicting_or_invalid_ttl_alias_cannot_be_silently_ignored(run_connector, tmp_path, extra):
    rows = _temporal_rows()
    rows[0].update(extra)
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete and found[("192.0.2.10", "provider.openai")].metadata["flows"] == 0


def test_equivalent_context_and_ttl_aliases_remain_usable(run_connector, tmp_path):
    rows = _temporal_rows()
    rows[0].update(sensor="one", sensor_id=" one ", ttl=60, ttls="60")
    rows[1].update(sensor_id="one")
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert not stats.incomplete and found[("192.0.2.10", "provider.openai")].metadata["flows"] == 1


def test_ja4_cap_cannot_hide_a_conflicting_fingerprint(run_connector, tmp_path, monkeypatch):
    monkeypatch.setattr(network_logs, "_MAX_JA4_PER_CONTACT", 1)
    row = json.loads((FIXTURES / "ja4_ssl.jsonl").read_text().splitlines()[0])
    rows = [row, {**row, "ja4": "t13d1516h2_000000000000_000000000000"}, dict(row)]
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    assert stats.incomplete and "tls_fingerprints" not in found[("192.0.2.10", "provider.openai")].metadata


def test_cadence_does_not_combine_separate_sensor_contexts(run_connector, tmp_path):
    rows = [
        {
            "client": "192.0.2.10",
            "sni": "api.openai.com",
            "ts": 1000 + index,
            "sensor": sensor,
            "uid": f"C{index}",
        }
        for index, sensor in enumerate(("one", "two", "one"))
    ]
    found, stats = _scan_network_rows(run_connector, tmp_path, rows)
    finding = found[("192.0.2.10", "provider.openai")]
    assert not stats.incomplete and finding.confidence == 0.7
    assert "agent-loop" not in finding.tags and "loop_cadence" not in finding.metadata
    assert any("combines observation contexts" in item for item in finding.metadata["limitations"])
