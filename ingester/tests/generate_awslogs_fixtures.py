#!/usr/bin/env python3
"""Generate ``tests/testdata_awslogs/`` — a miniature verbatim S3 copy of ``AWSLogs/``.

The tree holds one file of every kind ``log_kind::classify`` distinguishes, plus
the flow log formats and corruptions the parser must survive (PRD_VPC_FLOW_LOGS
§8 Phase 0). Records follow the AWS record examples, re-dated to 2024-01-15.

Run from ``ingester/``:
    python3 tests/generate_awslogs_fixtures.py

Output is deterministic (gzip ``mtime=0``), so a re-run is a no-op diff.
"""

from __future__ import annotations

import gzip
import shutil
from pathlib import Path

ROOT = Path(__file__).parent / "testdata_awslogs"
ACCT = "123456789012"
DEFAULT = f"AWSLogs/{ACCT}"
FLOW_DIR = f"{DEFAULT}/vpcflowlogs/us-east-1/2024/01/15"
HIVE_DIR = (
    f"AWSLogs/aws-account-id={ACCT}/aws-service=vpcflowlogs/aws-region=us-east-1"
    "/year=2024/month=01/day=16"
)

V2_HEADER = (
    "version account-id interface-id srcaddr dstaddr srcport dstport protocol "
    "packets bytes start end action log-status"
)
# Custom format: reordered (flow-direction second), v3–v8 fields, and a field
# Senrigan does not know, which must land in `extra`.
CUSTOM_HEADER = (
    "version flow-direction account-id interface-id srcaddr dstaddr srcport dstport "
    "protocol packets bytes start end action log-status vpc-id subnet-id instance-id "
    "tcp-flags type pkt-srcaddr pkt-dstaddr traffic-path pkt-src-aws-service "
    "pkt-dst-aws-service reject-reason future-field"
)
T0, T1 = 1705276800, 1705276860  # 2024-01-15 00:00:00Z → 00:01:00Z
T2, T3 = 1705363200, 1705363260  # 2024-01-16 00:00:00Z → 00:01:00Z


def flow_name(flow_log_id: str, stamp: str, tag: str, ext: str = "log.gz") -> str:
    return f"{ACCT}_vpcflowlogs_us-east-1_{flow_log_id}_{stamp}_{tag}.{ext}"


def write(rel: str, body: bytes | str) -> None:
    path = ROOT / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    data = body.encode() if isinstance(body, str) else body
    if rel.endswith(".gz"):
        with path.open("wb") as raw, gzip.GzipFile(
            fileobj=raw, mode="wb", mtime=0, filename=""
        ) as gz:
            gz.write(data)
    else:
        path.write_bytes(data)


def lines(*rows: str) -> str:
    return "\n".join(rows) + "\n"


def main() -> None:
    shutil.rmtree(ROOT, ignore_errors=True)

    # CloudTrail — the existing pipeline, one record.
    write(
        f"{DEFAULT}/CloudTrail/us-east-1/2024/01/15/"
        f"{ACCT}_CloudTrail_us-east-1_20240115T0000Z_fx01.json.gz",
        (Path(__file__).parent / "testdata" / "single_event.json").read_text(),
    )

    # v2 default: TCP accept/reject, ICMP (ports are 0), IPv6, NODATA, SKIPDATA.
    eni = "eni-1235b8ca123456789"
    write(
        f"{FLOW_DIR}/{flow_name('fl-0a1b2c3d', '20240115T0000Z', 'v2')}",
        lines(
            V2_HEADER,
            f"2 {ACCT} {eni} 172.31.16.139 172.31.16.21 20641 22 6 20 4249 {T0} {T1} ACCEPT OK",
            f"2 {ACCT} {eni} 172.31.9.69 172.31.9.12 49761 3389 6 20 4249 {T0} {T1} REJECT OK",
            f"2 {ACCT} {eni} 81.2.69.160 172.31.16.139 0 0 1 4 336 {T0} {T1} ACCEPT OK",
            f"2 {ACCT} {eni} 2001:db8:1234:a100:8d6e:3477:df66:f105 "
            f"2001:db8:1234:a102:3304:8879:34cf:4071 34892 22 6 54 8855 {T0} {T1} ACCEPT OK",
            f"2 {ACCT} {eni} - - - - - - - {T0} {T1} - NODATA",
            f"2 {ACCT} eni-11111111aaaaaaaaa - - - - - - - {T0} {T1} - SKIPDATA",
        ),
    )

    # Custom v8 format: S3 ingress/egress, NAT gateway egress, BPA reject, UDP 53.
    vpc, subnet, inst = (
        "vpc-abcdefab012345678",
        "subnet-aaaaaaaa012345678",
        "i-0c50d5961bcb2d47b",
    )

    def custom(
        direction,
        src,
        dst,
        sport,
        dport,
        proto,
        pkts,
        nbytes,
        action,
        flags,
        psrc,
        pdst,
        path,
        src_svc,
        dst_svc,
        reject,
        t0=T0,
        t1=T1,
        iface=eni,
        instance=inst,
    ):
        return (
            f"8 {direction} {ACCT} {iface} {src} {dst} {sport} {dport} {proto} {pkts} "
            f"{nbytes} {t0} {t1} {action} OK {vpc} {subnet} {instance} {flags} IPv4 "
            f"{psrc} {pdst} {path} {src_svc} {dst_svc} {reject} x"
        )

    write(
        f"{FLOW_DIR}/{flow_name('fl-0e4f5a6b', '20240115T0005Z', 'v8')}",
        lines(
            CUSTOM_HEADER,
            custom(
                "ingress",
                "52.95.128.179",
                "10.0.0.71",
                80,
                34210,
                6,
                14,
                15044,
                "ACCEPT",
                19,
                "52.95.128.179",
                "10.0.0.71",
                "-",
                "S3",
                "-",
                "-",
            ),
            custom(
                "egress",
                "10.0.0.71",
                "52.95.128.179",
                34210,
                80,
                6,
                7,
                471,
                "ACCEPT",
                3,
                "10.0.0.71",
                "52.95.128.179",
                8,
                "-",
                "S3",
                "-",
            ),
            custom(
                "egress",
                "10.0.1.5",
                "10.0.0.220",
                40000,
                443,
                6,
                10,
                900,
                "ACCEPT",
                2,
                "10.0.1.5",
                "81.2.69.160",
                1,
                "-",
                "-",
                "-",
                iface="eni-0aaaaaaaaaaaaaaaa",
                instance="-",
            ),
            custom(
                "ingress",
                "81.2.69.160",
                "10.0.0.71",
                51515,
                22,
                6,
                1,
                "-",
                "REJECT",
                2,
                "81.2.69.160",
                "10.0.0.71",
                "-",
                "-",
                "-",
                "BPA",
            ),
            custom(
                "egress",
                "10.0.0.71",
                "8.8.8.8",
                53000,
                53,
                17,
                2,
                120,
                "ACCEPT",
                0,
                "10.0.0.71",
                "8.8.8.8",
                8,
                "-",
                "-",
                "-",
            ),
        ),
    )

    # Hive-compatible prefix, next day, same subscription.
    write(
        f"{HIVE_DIR}/{flow_name('fl-0e4f5a6b', '20240116T0000Z', 'hive')}",
        lines(
            CUSTOM_HEADER,
            custom(
                "egress",
                "10.0.0.71",
                "81.2.69.160",
                40001,
                443,
                6,
                10,
                900,
                "ACCEPT",
                2,
                "10.0.0.71",
                "81.2.69.160",
                8,
                "-",
                "-",
                "-",
                T2,
                T3,
            ),
            custom(
                "ingress",
                "81.2.69.160",
                "10.0.0.71",
                443,
                40001,
                6,
                10,
                900,
                "ACCEPT",
                18,
                "81.2.69.160",
                "10.0.0.71",
                "-",
                "-",
                "-",
                "-",
                T2,
                T3,
            ),
        ),
    )

    # Corruption inside a readable file: one good row, one malformed numeric
    # (kept, flagged), one short row (rejected).
    write(
        f"{FLOW_DIR}/{flow_name('fl-0a1b2c3d', '20240115T0010Z', 'bad')}",
        lines(
            V2_HEADER,
            f"2 {ACCT} {eni} 10.0.0.1 10.0.0.2 40000 443 6 10 900 {T0} {T1} ACCEPT OK",
            f"2 {ACCT} {eni} 10.0.0.1 10.0.0.3 40000 443 6 10 abc {T0} {T1} ACCEPT OK",
            f"2 {ACCT} {eni} 10.0.0.1",
        ),
    )

    # Whole-file failure: named as a flow log, not gzip.
    corrupt = ROOT / FLOW_DIR / flow_name("fl-0a1b2c3d", "20240115T0015Z", "corrupt")
    corrupt.write_bytes(b"\x1f\x8b this is not a gzip stream")

    # Header-only: valid, zero rows.
    write(
        f"{FLOW_DIR}/{flow_name('fl-0a1b2c3d', '20240115T0020Z', 'empty')}",
        lines(V2_HEADER),
    )

    # Skipped kinds.
    write(
        f"{FLOW_DIR}/{flow_name('fl-0a1b2c3d', '20240115T0025Z', 'pq', 'log.parquet')}",
        b"PAR1",
    )
    write(
        f"{DEFAULT}/CloudTrail-Digest/us-east-1/2024/01/15/"
        f"{ACCT}_CloudTrail-Digest_us-east-1_trail_us-east-1_20240115T000000Z.json.gz",
        '{"digestStartTime":"2024-01-15T00:00:00Z"}',
    )
    write(
        f"{DEFAULT}/Config/us-east-1/2024/1/15/ConfigSnapshot/"
        f"{ACCT}_Config_us-east-1_ConfigSnapshot_20240115T000000Z_fx01.json.gz",
        '{"configurationItems":[]}',
    )
    write(
        f"{DEFAULT}/elasticloadbalancing/us-east-1/2024/01/15/"
        f"{ACCT}_elasticloadbalancing_us-east-1_app.my-lb.1_20240115T0000Z_10.0.0.1_x.log.gz",
        "https 2024-01-15T00:00:00.000000Z app/my-lb/1 1.2.3.4:5 10.0.0.1:80 0.001 0.002 "
        '0.000 200 200 34 366 "GET https://x/ HTTP/1.1"\n',
    )


if __name__ == "__main__":
    main()
