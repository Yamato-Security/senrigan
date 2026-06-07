"""Extract AWS service icons for the config_viz frontend.

This script runs at Docker build time to populate ``/icons/`` with PNG icons
for each AWS resource type understood by the frontend.  It is intentionally
forgiving: if a download fails the script exits 0 so that a network outage
cannot break the Docker image build.  The frontend falls back to
``/icons/default.png`` for any icon that is missing.

Usage::

    python extract_icons.py <output_dir>

The script always creates ``<output_dir>/default.png`` (a minimal grey square)
regardless of network availability.
"""

import struct
import sys
import urllib.error
import urllib.request
import zlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Mapping: frontend icon filename → source URL
#
# Icons are fetched from the community-maintained aws-icons-for-plantuml
# GitHub release artefacts (PNG, 64 px, transparent background).
# URL template:
#   https://raw.githubusercontent.com/awslabs/aws-icons-for-plantuml
#       /v20.0/dist/<Category>/<Service>.png
# ---------------------------------------------------------------------------

_BASE = "https://raw.githubusercontent.com/awslabs/aws-icons-for-plantuml" "/v20.0/dist"

ICON_SOURCES: dict[str, str] = {
    "EC2_Instance.png": f"{_BASE}/Compute/EC2Instance.png",
    "VPC.png": f"{_BASE}/NetworkingContentDelivery/VirtualPrivateCloud.png",
    "Subnet.png": f"{_BASE}/NetworkingContentDelivery/VPCSubnet.png",
    "Security_Group.png": f"{_BASE}/SecurityIdentityCompliance/WAF.png",
    "Internet_Gateway.png": f"{_BASE}/NetworkingContentDelivery/InternetGateway.png",
    "Route_Table.png": f"{_BASE}/NetworkingContentDelivery/RouteTable.png",
    "Network_Interface.png": f"{_BASE}/NetworkingContentDelivery/ElasticNetworkInterface.png",
    "Elastic_IP.png": f"{_BASE}/NetworkingContentDelivery/ElasticIPAddress.png",
    "S3_Bucket.png": f"{_BASE}/Storage/SimpleStorageService.png",
    "IAM_Role.png": f"{_BASE}/SecurityIdentityCompliance/Role.png",
    "IAM_User.png": f"{_BASE}/SecurityIdentityCompliance/User.png",
    "IAM_Group.png": f"{_BASE}/SecurityIdentityCompliance/Group.png",
    "IAM_Policy.png": f"{_BASE}/SecurityIdentityCompliance/Permissions.png",
    "Lambda_Function.png": f"{_BASE}/Compute/LambdaFunction.png",
    "RDS_Instance.png": f"{_BASE}/Database/RDSInstance.png",
    "RDS_Subnet_Group.png": f"{_BASE}/Database/RDSDBSubnetGroup.png",
    "CloudTrail.png": f"{_BASE}/ManagementGovernance/CloudTrail.png",
    "CloudFormation.png": f"{_BASE}/ManagementGovernance/CloudFormation.png",
    "ELB.png": f"{_BASE}/NetworkingContentDelivery/ElasticLoadBalancing.png",
    "Target_Group.png": f"{_BASE}/NetworkingContentDelivery/ElasticLoadBalancing.png",
    "Auto_Scaling.png": f"{_BASE}/ManagementGovernance/AutoScaling.png",
    "ECS_Cluster.png": f"{_BASE}/Containers/ElasticContainerService.png",
    "ECS_Service.png": f"{_BASE}/Containers/ECSService.png",
    "EKS_Cluster.png": f"{_BASE}/Containers/ElasticKubernetesService.png",
    "SNS_Topic.png": f"{_BASE}/ApplicationIntegration/SimpleNotificationService.png",
    "SQS_Queue.png": f"{_BASE}/ApplicationIntegration/SimpleQueueService.png",
    "DynamoDB_Table.png": f"{_BASE}/Database/DynamoDB.png",
    "KMS_Key.png": f"{_BASE}/SecurityIdentityCompliance/KeyManagementService.png",
    "CloudWatch_Logs.png": f"{_BASE}/ManagementGovernance/CloudWatchLogs.png",
    # Additional icons for real-world resource types
    "IAM_InstanceProfile.png": f"{_BASE}/SecurityIdentityCompliance/Role.png",
    "IAM_ManagedPolicy.png": f"{_BASE}/SecurityIdentityCompliance/Permissions.png",
    "CodeDeploy.png": f"{_BASE}/DeveloperTools/CodeDeploy.png",
    "Backup.png": f"{_BASE}/Storage/Backup.png",
    "CloudFront.png": f"{_BASE}/NetworkingContentDelivery/CloudFront.png",
    "ECR.png": f"{_BASE}/Containers/ElasticContainerRegistry.png",
    "SecretsManager.png": f"{_BASE}/SecurityIdentityCompliance/SecretsManager.png",
    "StepFunctions.png": f"{_BASE}/ApplicationIntegration/StepFunctions.png",
    "EventBridge.png": f"{_BASE}/ApplicationIntegration/EventBridge.png",
    "Glue.png": f"{_BASE}/Analytics/Glue.png",
    "Athena.png": f"{_BASE}/Analytics/Athena.png",
}

# ---------------------------------------------------------------------------
# Fallback: generate a minimal valid 32×32 grey PNG without any dependencies
# ---------------------------------------------------------------------------


def _build_png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Return a valid PNG chunk (length + type + data + CRC)."""
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc


def _make_grey_png(size: int = 32, grey: int = 0xCC) -> bytes:
    """Return the bytes of a minimal greyscale PNG of *size* × *size* pixels."""
    # IHDR: width, height, bit-depth=8, colour-type=0 (greyscale),
    #       compression=0, filter=0, interlace=0
    ihdr_data = struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0)

    # Raw image data: one filter byte (0 = None) + size grey bytes per row
    raw_rows = (b"\x00" + bytes([grey] * size)) * size
    idat_data = zlib.compress(raw_rows, level=9)

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = _build_png_chunk(b"IHDR", ihdr_data)
    idat = _build_png_chunk(b"IDAT", idat_data)
    iend = _build_png_chunk(b"IEND", b"")
    return signature + ihdr + idat + iend


# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------


def _download(url: str, dest: Path, timeout: int = 10) -> bool:
    """Download *url* to *dest*.  Returns True on success, False on failure."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            dest.write_bytes(resp.read())
        return True
    except (urllib.error.URLError, OSError) as exc:
        print(f"  [warn] Failed to download {url}: {exc}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(output_dir: str) -> None:
    """Populate *output_dir* with AWS service icons.

    Always creates ``default.png``; attempts to download the rest.

    Args:
        output_dir: Filesystem path to the icons output directory.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Always write the greyscale fallback icon
    default_path = out / "default.png"
    default_path.write_bytes(_make_grey_png(32, grey=0xCC))
    print(f"[ok] Created {default_path}")

    # Attempt to download each icon from the remote source
    ok = 0
    fail = 0
    for filename, url in ICON_SOURCES.items():
        dest = out / filename
        if dest.exists():
            print(f"[skip] {filename} already exists")
            ok += 1
            continue
        print(f"Downloading {filename} ...", end=" ", flush=True)
        if _download(url, dest):
            print("ok")
            ok += 1
        else:
            fail += 1

    print(
        f"\nIcons: {ok} downloaded/cached, {fail} failed"
        f" (will use default.png fallback).",
        file=sys.stderr,
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output_dir>", file=sys.stderr)
        sys.exit(1)
    main(sys.argv[1])
