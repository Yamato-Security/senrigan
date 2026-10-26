#!/usr/bin/env python3
"""Generate the VPC Flow Logs fixture database for the Senrigan test suites.

The dashboard bundle and the agent's flow hunts are tested by running their SQL
against a real database, and a hunt is only trusted when it finds a planted
positive *and* ignores a near-miss beside it (PRD_VPC_FLOW_LOGS §7–§8). This
script writes a synthetic two-day ``AWSLogs/`` tree holding those scenarios,
then runs the real ingester over it, so the fixture has exactly the schema,
derived columns, views and ``ip_geo`` rows a user's database would have.

Usage::

    python3 sample/vpc_flow/generate_fixtures.py

Requires ``cargo`` (the ingester is built and run in release mode). Addresses
are chosen from MaxMind's GeoLite2 *test* databases bundled with the ingester,
so GeoIP charts have data. Day 0 (2024-01-14) is a quiet baseline; Day 1
(2024-01-15) holds the incident. The scenario catalogue is :data:`SCENARIOS`,
which the tests import so expectations and data cannot drift apart.

Like the Suzaku fixtures, the output is content-reproducible, not
byte-reproducible: DuckDB block layout differs between writes.
"""

from __future__ import annotations

import gzip
import json
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
INGESTER = REPO / "ingester"
GEOIP = INGESTER / "tests" / "testdata" / "geoip"
OUT = Path(__file__).resolve().parent / "fixtures" / "vpc-flow-fixture.duckdb"

ACCT = "123456789012"
MAIN, LEGACY = "fl-0a1b2c3d4e5f60001", "fl-0f1e2d3c4b5a60002"
DAY0 = datetime(2024, 1, 14, tzinfo=UTC)
DAY1 = datetime(2024, 1, 15, tzinfo=UTC)

# The custom format of the main subscription: version 11 fields, reordered.
MAIN_FIELDS = (
    "version flow-direction account-id interface-id srcaddr dstaddr srcport dstport "
    "protocol packets bytes start end action log-status vpc-id subnet-id instance-id "
    "tcp-flags type pkt-srcaddr pkt-dstaddr traffic-path pkt-src-aws-service "
    "pkt-dst-aws-service reject-reason encryption-status interface-type resource-id"
).split()
V2_FIELDS = (
    "version account-id interface-id srcaddr dstaddr srcport dstport protocol "
    "packets bytes start end action log-status"
).split()

# Scenario name -> the addresses tests use to find it. Positives first, then the
# near-miss each hunt must not report.
SCENARIOS = {
    "vertical_scan": {"remote": "175.16.199.10", "local": "10.0.1.10", "ports": 60},
    "vertical_near_miss": {"remote": "216.160.83.56", "local": "10.0.1.10"},
    "horizontal_scan": {"remote": "89.160.20.112", "port": 22, "targets": 30},
    "admin_rdp_accepted": {"remote": "81.2.69.142", "local": "10.0.1.20", "port": 3389},
    "admin_ssh_accepted": {"remote": "2.125.160.216", "local": "10.0.1.21", "port": 22},
    "reject_then_accept": {"remote": "89.160.20.128", "local": "10.0.1.21", "port": 22},
    "beacon": {"local": "10.0.2.5", "remote": "202.196.224.10", "port": 443},
    "beacon_with_skipdata": {"local": "10.0.2.15", "remote": "202.196.224.11"},
    "cadence_near_miss": {"local": "10.0.2.6", "remote": "52.95.128.179"},
    "exfil": {"local": "10.0.2.7", "remote": "67.43.156.10"},
    "staging_source": {"local": "10.0.3.5"},
    "c2_port": {"local": "10.0.2.8", "remote": "175.16.199.20", "port": 4444},
    "mining_port": {"local": "10.0.2.9", "remote": "1.128.0.10", "port": 3333},
    "dns_custom_resolver": {"local": "10.0.2.10", "remote": "8.8.8.8"},
    "smtp_out": {"local": "10.0.2.11", "remote": "216.160.83.56"},
    "lateral_smb": {"src": "10.0.1.20", "targets": 10, "port": 445},
    "lateral_near_miss": {"src": "10.0.2.5", "dst": "10.0.3.5", "port": 5432},
    "icmp": {"remote": "81.2.69.160", "local": "10.0.1.10"},
    "icmpv6": {"remote": "2a02:cf40::1", "local": "2600:1f18:0:1::5"},
    "ipv6_egress": {"local": "2600:1f18:0:1::5", "remote": "2001:480::1"},
    "udp_fanout": {"local": "10.0.2.12", "targets": 30, "port": 19},
    "gre": {"local": "10.0.2.13", "remote": "175.16.199.30"},
    "bpa_reject": {"remote": "81.2.69.160", "local": "10.0.1.40"},
    "nat_egress": {"interface": "eni-0aa0000000000001", "remote": "81.2.69.160"},
}

# Host address -> (ENI, instance, subnet).
HOSTS: dict[str, tuple[str, str, str]] = {}


def host(addr: str) -> tuple[str, str, str]:
    """Return the ENI, instance and subnet owning `addr`, inventing them once."""
    if addr not in HOSTS:
        n = len(HOSTS) + 1
        subnet = {
            "10.0.1": "subnet-0a00000000000001",
            "10.0.2": "subnet-0a00000000000002",
            "10.0.3": "subnet-0a00000000000003",
        }.get(addr.rsplit(".", 1)[0], "subnet-0a00000000000004")
        HOSTS[addr] = (f"eni-0{n:016x}", f"i-0{n:016x}", subnet)
    return HOSTS[addr]


class Recorder:
    """Collects flow records per (subscription, 5-minute object)."""

    def __init__(self) -> None:
        self.files: dict[tuple[str, datetime], list[str]] = defaultdict(list)
        self.counter = 0

    def _put(self, sub: str, t: datetime, row: str) -> None:
        window = t.replace(minute=t.minute - t.minute % 5, second=0)
        self.files[(sub, window)].append(row)

    def flow(
        self,
        t: datetime,
        direction: str,
        iface_addr: str,
        src: str,
        dst: str,
        sport: int,
        dport: int,
        proto: int = 6,
        packets: int = 10,
        nbytes: int | str = 900,
        action: str = "ACCEPT",
        flags: int | str = 3,
        path: int | str = "-",
        src_svc: str = "-",
        dst_svc: str = "-",
        reject: str = "-",
        itype: str = "-",
        iface: str | None = None,
        psrc: str | None = None,
        pdst: str | None = None,
        duration: int = 60,
    ) -> None:
        """One record on the interface owning `iface_addr` (or `iface`)."""
        eni, inst, subnet = host(iface_addr)
        if iface is not None:
            eni, inst = iface, "-"
        family = "IPv6" if ":" in src else "IPv4"
        self.counter += 1
        enc = ("0", "1", "2", "3", "-")[self.counter % 5]
        start = int(t.timestamp())
        values = {
            "version": "11",
            "flow-direction": direction,
            "account-id": ACCT,
            "interface-id": eni,
            "srcaddr": src,
            "dstaddr": dst,
            "srcport": str(sport),
            "dstport": str(dport),
            "protocol": str(proto),
            "packets": str(packets),
            "bytes": str(nbytes),
            "start": str(start),
            "end": str(start + duration),
            "action": action,
            "log-status": "OK",
            "vpc-id": "vpc-0a1b2c3d4e5f60001",
            "subnet-id": subnet,
            "instance-id": inst,
            "tcp-flags": str(flags) if proto == 6 else "0",
            "type": family,
            "pkt-srcaddr": psrc or src,
            "pkt-dstaddr": pdst or dst,
            "traffic-path": str(path),
            "pkt-src-aws-service": src_svc,
            "pkt-dst-aws-service": dst_svc,
            "reject-reason": reject,
            "encryption-status": enc,
            "interface-type": itype,
            "resource-id": "-",
        }
        self._put(MAIN, t, " ".join(values[f] for f in MAIN_FIELDS))

    def internal(self, t: datetime, src: str, dst: str, dport: int, **kw) -> None:
        """An intra-VPC flow, observed on both ENIs as AWS records it."""
        sport = kw.pop("sport", 49152)
        self.flow(t, "egress", src, src, dst, sport, dport, path=1, **kw)
        self.flow(t, "ingress", dst, src, dst, sport, dport, **kw)

    def status(self, t: datetime, iface_addr: str, status: str) -> None:
        eni = host(iface_addr)[0]
        start = int(t.timestamp())
        values = dict.fromkeys(MAIN_FIELDS, "-")
        values.update(
            {
                "version": "11",
                "account-id": ACCT,
                "interface-id": eni,
                "start": str(start),
                "end": str(start + 60),
                "log-status": status,
            }
        )
        self._put(MAIN, t, " ".join(values[f] for f in MAIN_FIELDS))

    def legacy(
        self,
        t: datetime,
        eni: str,
        src: str,
        dst: str,
        sport,
        dport,
        proto=6,
        action="ACCEPT",
        status="OK",
    ) -> None:
        """A version-2 default record: no direction, no packet addresses."""
        start = int(t.timestamp())
        if status != "OK":
            row = f"2 {ACCT} {eni} - - - - - - - {start} {start + 60} - {status}"
        else:
            row = (
                f"2 {ACCT} {eni} {src} {dst} {sport} {dport} {proto} 10 900 "
                f"{start} {start + 60} {action} OK"
            )
        self._put(LEGACY, t, row)


def at(day: datetime, hh: int, mm: int = 0, ss: int = 0) -> datetime:
    return day + timedelta(hours=hh, minutes=mm, seconds=ss)


def build(rec: Recorder) -> None:
    s = SCENARIOS

    # ── Day 0: quiet baseline ───────────────────────────────────────────
    for h in range(24):
        # The exfil host's normal day: small HTTPS to one partner.
        rec.flow(
            at(DAY0, h, 10),
            "egress",
            "10.0.2.7",
            "10.0.2.7",
            "216.160.83.56",
            50000 + h,
            443,
            nbytes=10_000,
            path=8,
        )
        # App → DB on Postgres: an established internal pair (lateral near-miss).
        rec.internal(at(DAY0, h, 20), "10.0.2.5", "10.0.3.5", 5432, nbytes=50_000)

    # ── Day 1: inbound reconnaissance and access ─────────────────────────
    vs = s["vertical_scan"]
    for i in range(vs["ports"]):
        rec.flow(
            at(DAY1, 1, 0, i),
            "ingress",
            vs["local"],
            vs["remote"],
            vs["local"],
            40000 + i,
            1 + i,
            packets=1,
            nbytes=44,
            action="REJECT",
            flags=2,
        )
    nm = s["vertical_near_miss"]
    for port in (80, 443):
        rec.flow(
            at(DAY1, 1, 10),
            "ingress",
            nm["local"],
            nm["remote"],
            nm["local"],
            51000,
            port,
            flags=3,
        )

    hs = s["horizontal_scan"]
    for i in range(hs["targets"]):
        target = f"10.0.1.{100 + i}"
        rec.flow(
            at(DAY1, 1, 30, i),
            "ingress",
            target,
            hs["remote"],
            target,
            41000 + i,
            hs["port"],
            packets=1,
            nbytes=44,
            action="REJECT",
            flags=2,
        )

    for key in ("admin_rdp_accepted", "admin_ssh_accepted"):
        a = s[key]
        rec.flow(
            at(DAY1, 2),
            "ingress",
            a["local"],
            a["remote"],
            a["local"],
            52000,
            a["port"],
            nbytes=50_000,
            flags=3,
        )

    ra = s["reject_then_accept"]
    rec.flow(
        at(DAY1, 2, 30),
        "ingress",
        ra["local"],
        ra["remote"],
        ra["local"],
        53000,
        ra["port"],
        packets=1,
        nbytes=44,
        action="REJECT",
        flags=2,
    )
    rec.flow(
        at(DAY1, 3, 30),
        "ingress",
        ra["local"],
        ra["remote"],
        ra["local"],
        53001,
        ra["port"],
        nbytes=8_000,
        flags=3,
    )

    bpa = s["bpa_reject"]
    rec.flow(
        at(DAY1, 10),
        "ingress",
        bpa["local"],
        bpa["remote"],
        bpa["local"],
        54000,
        22,
        packets=1,
        nbytes="-",
        action="REJECT",
        flags=2,
        reject="BPA",
    )
    for h in (11, 12, 13):
        rec.status(at(DAY1, h), bpa["local"], "NODATA")

    ic = s["icmp"]
    rec.flow(
        at(DAY1, 8),
        "ingress",
        ic["local"],
        ic["remote"],
        ic["local"],
        0,
        0,
        proto=1,
        packets=4,
        nbytes=336,
    )
    v6 = s["icmpv6"]
    rec.flow(
        at(DAY1, 8, 5),
        "ingress",
        v6["local"],
        v6["remote"],
        v6["local"],
        0,
        0,
        proto=58,
        packets=4,
        nbytes=336,
    )

    # ── Day 1: egress ────────────────────────────────────────────────────
    b = s["beacon"]
    for i in range(288):
        rec.flow(
            DAY1 + timedelta(minutes=5 * i, seconds=7),
            "egress",
            b["local"],
            b["local"],
            b["remote"],
            44000 + i,
            b["port"],
            packets=6,
            nbytes=620 + (i % 3) * 5,
            flags=3,
            path=8,
        )
    bs = s["beacon_with_skipdata"]
    for i in range(288):
        t = DAY1 + timedelta(minutes=5 * i, seconds=11)
        if 100 <= i < 140:
            if i % 5 == 0:
                rec.status(t, bs["local"], "SKIPDATA")
            continue
        rec.flow(
            t,
            "egress",
            bs["local"],
            bs["local"],
            bs["remote"],
            45000 + i,
            443,
            packets=6,
            nbytes=640,
            flags=3,
            path=8,
        )

    cn = s["cadence_near_miss"]
    for i in range(1440):
        rec.flow(
            DAY1 + timedelta(minutes=i),
            "egress",
            cn["local"],
            cn["local"],
            cn["remote"],
            46000 + i % 1000,
            443,
            nbytes=1_200,
            path=(8, 7, 2)[i % 3],
            dst_svc="S3",
        )
    rec.flow(
        at(DAY1, 23, 59, 30),
        "egress",
        cn["local"],
        cn["local"],
        cn["remote"],
        47000,
        443,
        action="REJECT",
        reject="EC",
        dst_svc="S3",
        path=7,
    )

    stg = s["staging_source"]["local"]
    ex = s["exfil"]
    for i in range(4):
        rec.internal(
            at(DAY1, 3, 30 + i), stg, ex["local"], 445, sport=5432, nbytes=500_000_000
        )
    for i in range(12):
        rec.flow(
            at(DAY1, 4, 5 * i),
            "egress",
            ex["local"],
            ex["local"],
            ex["remote"],
            48000 + i,
            443,
            packets=300_000,
            nbytes=400_000_000,
            path=8,
        )

    for key, proto in (("c2_port", 6), ("mining_port", 6)):
        c = s[key]
        for i in range(6):
            rec.flow(
                at(DAY1, 6, 10 * i),
                "egress",
                c["local"],
                c["local"],
                c["remote"],
                49000 + i,
                c["port"],
                proto=proto,
                path=8,
            )

    d = s["dns_custom_resolver"]
    for i in range(5):
        rec.flow(
            at(DAY1, 7, i),
            "egress",
            d["local"],
            d["local"],
            d["remote"],
            53000 + i,
            53,
            proto=17,
            nbytes=120,
            path=8,
        )

    m = s["smtp_out"]
    for i in range(5):
        rec.flow(
            at(DAY1, 7, 30 + i),
            "egress",
            m["local"],
            m["local"],
            m["remote"],
            55000 + i,
            25,
            path=8,
        )

    u = s["udp_fanout"]
    for i in range(u["targets"]):
        rec.flow(
            at(DAY1, 9, 0, i),
            "egress",
            u["local"],
            u["local"],
            f"12.81.92.{1 + i}",
            56000 + i,
            u["port"],
            proto=17,
            nbytes=64,
            path=8,
        )

    g = s["gre"]
    rec.flow(
        at(DAY1, 9, 30),
        "egress",
        g["local"],
        g["local"],
        g["remote"],
        0,
        0,
        proto=47,
        nbytes=5_000,
        path=8,
    )

    e6 = s["ipv6_egress"]
    rec.flow(
        at(DAY1, 9, 40),
        "egress",
        e6["local"],
        e6["local"],
        e6["remote"],
        57000,
        443,
        nbytes=20_000,
        path=8,
    )

    nat = s["nat_egress"]
    rec.flow(
        at(DAY1, 11),
        "egress",
        "10.0.0.220",
        "10.0.0.220",
        nat["remote"],
        58000,
        443,
        nbytes=30_000,
        path=8,
        iface=nat["interface"],
        itype="nat_gateway",
    )

    # ── Day 1: lateral movement ─────────────────────────────────────────
    lat = s["lateral_smb"]
    for i in range(lat["targets"]):
        rec.internal(
            at(DAY1, 5, 0, i), lat["src"], f"10.0.3.{1 + i}", lat["port"], nbytes=40_000
        )
    rec.internal(at(DAY1, 5, 5), lat["src"], "10.0.3.5", 3389, nbytes=80_000)
    nm = s["lateral_near_miss"]
    for h in range(24):
        rec.internal(at(DAY1, h, 20), nm["src"], nm["dst"], nm["port"], nbytes=50_000)

    # ── A second, legacy subscription: version 2, no direction ──────────
    for h in range(0, 24, 6):
        t = at(DAY1, h)
        rec.legacy(
            t, "eni-0be0000000000001", "172.31.16.139", "172.31.16.21", 20641, 22
        )
        rec.legacy(
            t, "eni-0be0000000000001", "81.2.69.160", "172.31.16.139", 51515, 443
        )
        rec.legacy(t, "eni-0be0000000000002", None, None, None, None, status="NODATA")


def cloudtrail_events() -> dict:
    """CreateFlowLogs for both subscriptions, so the capture scope is known."""

    def create(when: datetime, vpc: str, fl: str, traffic: str, fmt: str) -> dict:
        return {
            "eventTime": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventName": "CreateFlowLogs",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "81.2.69.142",
            "userIdentity": {
                "type": "IAMUser",
                "arn": f"arn:aws:iam::{ACCT}:user/netadmin",
                "accountId": ACCT,
            },
            "requestParameters": {
                "CreateFlowLogsRequest": {
                    "ResourceId": {"tag": 1, "content": vpc},
                    "ResourceType": "VPC",
                    "TrafficType": traffic,
                    "LogDestinationType": "s3",
                    "LogFormat": fmt,
                }
            },
            "responseElements": {
                "CreateFlowLogsResponse": {"flowLogIdSet": {"item": fl}}
            },
            "eventType": "AwsApiCall",
            "recipientAccountId": ACCT,
        }

    main_fmt = " ".join("${" + f + "}" for f in MAIN_FIELDS)
    return {
        "Records": [
            create(
                DAY0 - timedelta(days=30),
                "vpc-0a1b2c3d4e5f60001",
                MAIN,
                "ALL",
                main_fmt,
            ),
            create(
                DAY0 - timedelta(days=400), "vpc-0f1e2d3c4b5a60002", LEGACY, "ALL", ""
            ),
        ]
    }


def write_tree(rec: Recorder, root: Path) -> None:
    for n, ((sub, window), rows) in enumerate(sorted(rec.files.items())):
        stamp = window.strftime("%Y%m%dT%H%MZ")
        rel = (
            f"AWSLogs/{ACCT}/vpcflowlogs/us-east-1/{window:%Y/%m/%d}/"
            f"{ACCT}_vpcflowlogs_us-east-1_{sub}_{stamp}_{n:08x}.log.gz"
        )
        header = " ".join(MAIN_FIELDS if sub == MAIN else V2_FIELDS)
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("wb") as raw, gzip.GzipFile(
            fileobj=raw, mode="wb", mtime=0
        ) as gz:
            gz.write(("\n".join([header, *rows]) + "\n").encode())

    ct = root / f"AWSLogs/{ACCT}/CloudTrail/us-east-1/2024/01/14"
    ct.mkdir(parents=True, exist_ok=True)
    name = f"{ACCT}_CloudTrail_us-east-1_20240114T0000Z_fixture.json.gz"
    with (ct / name).open("wb") as raw, gzip.GzipFile(
        fileobj=raw, mode="wb", mtime=0
    ) as gz:
        gz.write(json.dumps(cloudtrail_events()).encode())


def main() -> None:
    rec = Recorder()
    build(rec)
    with tempfile.TemporaryDirectory() as tmp:
        tree, db = Path(tmp) / "logs", Path(tmp) / "fixture.duckdb"
        write_tree(rec, tree)
        subprocess.run(
            [
                "cargo",
                "run",
                "--release",
                "--quiet",
                "--manifest-path",
                str(INGESTER / "Cargo.toml"),
                "--",
                "ingest",
                "--path",
                str(tree),
                "--db",
                str(db),
                "--no-progress",
                "--geoip-city",
                str(GEOIP / "GeoLite2-City-Test.mmdb"),
                "--geoip-asn",
                str(GEOIP / "GeoLite2-ASN-Test.mmdb"),
            ],
            check=True,
        )
        OUT.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(db, OUT)
    print(f"wrote {OUT.relative_to(REPO)}", file=sys.stderr)


if __name__ == "__main__":
    main()
