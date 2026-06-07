import json
import re
from typing import Any

import duckdb

_FORBIDDEN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b",
    re.IGNORECASE,
)


class QueryValidationError(ValueError):
    pass


def validate_sql(sql: str) -> None:
    if _FORBIDDEN.search(sql):
        raise QueryValidationError(f"Write/DDL statements are not allowed: {sql[:120]}")


def _config_tables_exist(conn: duckdb.DuckDBPyConnection) -> bool:
    """Return True if config_snapshots table is present in the database."""
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables"
        " WHERE table_name = 'config_snapshots' LIMIT 1"
    ).fetchone()
    return row is not None


# ---------------------------------------------------------------------------
# Service-group helpers
# ---------------------------------------------------------------------------

# Human-readable labels for each AWS service namespace.
_SERVICE_LABELS: dict[str, str] = {
    "AppConfig": "AWS AppConfig",
    "Athena": "Amazon Athena",
    "AutoScaling": "Auto Scaling",
    "Backup": "AWS Backup",
    "Cassandra": "Amazon Keyspaces",
    "CloudFormation": "CloudFormation",
    "CloudTrail": "CloudTrail",
    "CodeDeploy": "AWS CodeDeploy",
    "Config": "AWS Config",
    "EC2": "Amazon EC2",
    "ECS": "Amazon ECS",
    "EKS": "Amazon EKS",
    "ElasticLoadBalancing": "Elastic Load Balancing",
    "ElasticLoadBalancingV2": "Elastic Load Balancing v2",
    "Events": "Amazon EventBridge",
    "Glue": "AWS Glue",
    "IAM": "AWS IAM",
    "KMS": "AWS KMS",
    "Lambda": "AWS Lambda",
    "Logs": "CloudWatch Logs",
    "RDS": "Amazon RDS",
    "S3": "Amazon S3",
    "Scheduler": "EventBridge Scheduler",
    "SNS": "Amazon SNS",
    "SQS": "Amazon SQS",
}


def _service_of(resource_type: str) -> str:
    """Extract service namespace: 'AWS::EC2::VPC' → 'EC2'."""
    parts = resource_type.split("::")
    return parts[1] if len(parts) >= 2 else "Other"


def _service_node_id(service_ns: str) -> str:
    """Return the synthetic node ID for a service-group node."""
    return f"__svc__{service_ns}"


def _build_parent_map(
    edge_rows: list[tuple[str, str, str]],
) -> dict[str, str]:
    """Build resource_id → parent_resource_id map from containment edges.

    Matches any edge whose type *starts with* one of the following
    (case-insensitive):

    * ``contains`` — src contains tgt; tgt's parent is src.
      Covers ``"Contains"``, ``"Contains Subnet"``, ``"Contains DBInstance"``, etc.
    * ``is contained in`` — src is inside tgt; src's parent is tgt.
      Covers ``"Is contained in Vpc"``, ``"Is contained in Subnet"``, etc.
    * ``is member of`` — src belongs to tgt; src's parent is tgt.
      Covers ``"Is member of AutoScalingGroup"`` and similar membership edges.
    """
    m: dict[str, str] = {}
    for src, tgt, etype in edge_rows:
        n = etype.strip().lower()
        if n.startswith("contains"):
            # src contains tgt → tgt's parent is src
            m[tgt] = src
        elif n.startswith("is contained in"):
            # src is contained in tgt → src's parent is tgt
            m[src] = tgt
        elif n.startswith("is member of"):
            # src is a member of tgt → src's parent is tgt
            m[src] = tgt
    return m


# Resource types that logically reside inside a VPC.
# When one of these has no VPC ancestor in the containment hierarchy, the
# inference step (_infer_vpc_for_residents) will try to find the VPC through
# non-containment ("Is associated with") edges.
_VPC_RESIDENT_TYPES: frozenset[str] = frozenset(
    {
        "AWS::EC2::Subnet",
        "AWS::EC2::RouteTable",
        "AWS::EC2::NetworkAcl",
        "AWS::EC2::NetworkInterface",
        "AWS::EC2::Instance",
        "AWS::EC2::NatGateway",
        "AWS::EC2::EIP",
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "AWS::ElasticLoadBalancing::LoadBalancer",
        "AWS::Lambda::Function",
        "AWS::RDS::DBSubnetGroup",
        "AWS::RDS::DBInstance",
    }
)

# Resource types that should be placed inside a specific Subnet when they have
# only association (non-containment) edges pointing to a Subnet.
# _infer_subnet_for_residents() runs BEFORE _infer_vpc_for_residents() so that
# these resources land at the most granular container available.
_SUBNET_RESIDENT_TYPES: frozenset[str] = frozenset(
    {
        "AWS::EC2::NetworkInterface",
        "AWS::Lambda::Function",
        "AWS::RDS::DBInstance",
    }
)

# S3 resource types that logically reside inside an S3 Bucket.
# When one of these has no parent yet, _infer_s3_hierarchy() will look for a
# direct S3::Bucket neighbour via any edge (including association edges) and
# assign that Bucket as the parent.
_S3_CHILD_TYPES: frozenset[str] = frozenset(
    {
        "AWS::S3::AccessPoint",
        "AWS::S3::MultiRegionAccessPoint",
    }
)


def _infer_subnet_for_residents(
    parent_map: dict[str, str],
    edge_rows: list[tuple[str, str, str]],
    rid_to_type: dict[str, str],
) -> None:
    """Mutate *parent_map* to place subnet-resident resources inside their Subnet.

    For each resource whose type is in ``_SUBNET_RESIDENT_TYPES`` and that has
    no parent yet, look for a direct neighbour that is an ``AWS::EC2::Subnet``
    via non-containment (association) edges and assign that Subnet as the parent.

    This runs **before** ``_infer_vpc_for_residents`` so that VPC inference can
    later confirm a VPC ancestor through the newly assigned Subnet parent.

    Args:
        parent_map:  Mutable mapping of resource_id → parent_resource_id.
        edge_rows:   All edges for the snapshot (source_id, target_id, edge_type).
        rid_to_type: resource_id → resource_type lookup.
    """
    # Build bidirectional adjacency of non-containment edges.
    assoc: dict[str, set[str]] = {}
    for src, tgt, etype in edge_rows:
        n = etype.strip().lower()
        if not n.startswith("contains") and not n.startswith("is contained in"):
            assoc.setdefault(src, set()).add(tgt)
            assoc.setdefault(tgt, set()).add(src)

    for rid, rtype in rid_to_type.items():
        if rtype not in _SUBNET_RESIDENT_TYPES:
            continue
        if rid in parent_map:
            continue  # already has a parent from containment edges
        # Look for a direct Subnet neighbour via association edges.
        for neighbor in assoc.get(rid, set()):
            if rid_to_type.get(neighbor) == "AWS::EC2::Subnet":
                parent_map[rid] = neighbor
                break


def _infer_vpc_for_residents(
    parent_map: dict[str, str],
    edge_rows: list[tuple[str, str, str]],
    rid_to_type: dict[str, str],
) -> None:
    """Mutate *parent_map* to place VPC-resident resources inside their VPC.

    For each resource whose type is in ``_VPC_RESIDENT_TYPES`` and that has no
    VPC ancestor in the current containment chain, walk non-containment
    ("Is associated with", etc.) edges via BFS to find a neighbour that *does*
    have a VPC ancestor, then assign the resource directly to that VPC.

    This handles resources such as ``AWS::EC2::EIP`` which carry only
    association edges (e.g. "Is associated with NAT Gateway") rather than
    explicit containment edges in the AWS Config snapshot.

    Args:
        parent_map:  Mutable mapping of resource_id → parent_resource_id
                     (already populated from containment edges).
        edge_rows:   All edges for the snapshot (source_id, target_id, edge_type).
        rid_to_type: resource_id → resource_type lookup.
    """

    def _vpc_ancestor(rid: str) -> str | None:
        """Return the first VPC resource_id in *rid*'s parent chain, or None."""
        seen: set[str] = set()
        cur = rid
        while cur and cur not in seen:
            seen.add(cur)
            parent = parent_map.get(cur)
            if parent is None:
                return None
            if rid_to_type.get(parent) == "AWS::EC2::VPC":
                return parent
            cur = parent
        return None

    # Build a bidirectional adjacency map of non-containment edges so we can
    # traverse "Is associated with" and similar relationships in both directions.
    assoc: dict[str, set[str]] = {}
    for src, tgt, etype in edge_rows:
        n = etype.strip().lower()
        if not n.startswith("contains") and not n.startswith("is contained in"):
            assoc.setdefault(src, set()).add(tgt)
            assoc.setdefault(tgt, set()).add(src)

    for rid, rtype in rid_to_type.items():
        if rtype not in _VPC_RESIDENT_TYPES:
            continue
        # Skip resources that already have a VPC ancestor.
        if _vpc_ancestor(rid) is not None:
            continue

        # BFS on association edges to find a neighbour with a VPC ancestor.
        visited: set[str] = {rid}
        queue: list[str] = list(assoc.get(rid, set()))
        found_vpc: str | None = None

        while queue and found_vpc is None:
            neighbor = queue.pop(0)
            if neighbor in visited:
                continue
            visited.add(neighbor)

            # Direct VPC?
            if rid_to_type.get(neighbor) == "AWS::EC2::VPC":
                found_vpc = neighbor
                break

            # Neighbour has a VPC ancestor through containment chain?
            vpc = _vpc_ancestor(neighbor)
            if vpc:
                found_vpc = vpc
                break

            queue.extend(n for n in assoc.get(neighbor, set()) if n not in visited)

        if found_vpc is not None:
            parent_map[rid] = found_vpc


def _infer_s3_hierarchy(
    parent_map: dict[str, str],
    edge_rows: list[tuple[str, str, str]],
    rid_to_type: dict[str, str],
) -> None:
    """Mutate *parent_map* to place S3 sub-resources inside their parent S3 Bucket.

    For each resource whose type is in ``_S3_CHILD_TYPES`` and that has no parent
    yet, look for a direct neighbour that is an ``AWS::S3::Bucket`` via any edge
    (containment or association) and assign that Bucket as the parent.

    AWS Config does not emit explicit containment edges for S3 AccessPoints; it
    uses association edges such as "Is associated with bucket".  This function
    bridges that gap so AccessPoints appear nested inside their Bucket in the graph.

    Args:
        parent_map:  Mutable mapping of resource_id → parent_resource_id.
        edge_rows:   All edges for the snapshot (source_id, target_id, edge_type).
        rid_to_type: resource_id → resource_type lookup.
    """
    # Build a bidirectional adjacency map across ALL edge types.
    adj: dict[str, set[str]] = {}
    for src, tgt, _etype in edge_rows:
        adj.setdefault(src, set()).add(tgt)
        adj.setdefault(tgt, set()).add(src)

    for rid, rtype in rid_to_type.items():
        if rtype not in _S3_CHILD_TYPES:
            continue
        if rid in parent_map:
            continue  # already has a parent from containment edges
        # Find a direct S3::Bucket neighbour.
        for neighbor in adj.get(rid, set()):
            if rid_to_type.get(neighbor) == "AWS::S3::Bucket":
                parent_map[rid] = neighbor
                break


# ---------------------------------------------------------------------------
# Public query functions
# ---------------------------------------------------------------------------


def snapshot_exists(conn: duckdb.DuckDBPyConnection, snapshot_id: str) -> bool:
    if not _config_tables_exist(conn):
        return False
    row = conn.execute(
        "SELECT 1 FROM config_snapshots WHERE snapshot_id = ? LIMIT 1",
        [snapshot_id],
    ).fetchone()
    return row is not None


def list_snapshots(conn: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    if not _config_tables_exist(conn):
        return []
    rows = conn.execute(
        "SELECT snapshot_id, account_id, aws_region,"
        " CAST(captured_at AS VARCHAR) AS captured_at,"
        " source_path, record_count"
        " FROM config_snapshots ORDER BY captured_at DESC"
    ).fetchall()
    cols = [
        "snapshot_id",
        "account_id",
        "aws_region",
        "captured_at",
        "source_path",
        "record_count",
    ]
    return [dict(zip(cols, r)) for r in rows]


def get_resource_types(
    conn: duckdb.DuckDBPyConnection,
    snapshot_id: str,
) -> list[str]:
    rows = conn.execute(
        "SELECT DISTINCT resource_type FROM config_resources"
        " WHERE snapshot_id = ? ORDER BY resource_type",
        [snapshot_id],
    ).fetchall()
    return [r[0] for r in rows]


def get_graph(
    conn: duckdb.DuckDBPyConnection,
    snapshot_id: str,
    resource_type: str | None = None,
    limit: int = 5000,
) -> dict[str, list[dict[str, Any]]]:
    """Return React Flow–compatible nodes and edges for a snapshot.

    Containment edges (``contains*`` / ``is contained in*``) are expressed
    via ``parentId`` on child nodes and are excluded from the edge list.

    When ``resource_type`` is given, service-group virtual nodes are **not**
    added to keep the filtered view clean.

    For each unique ``resource_id`` only the first ``resource_type`` is used
    when building the parent map from edges (edges store only the raw
    ``resource_id``).  Multiple resources that share a ``resource_id`` but
    differ in ``resource_type`` are all included as separate nodes; service
    grouping uses the actual ``resource_type`` of each row.
    """
    # 1. All edges for this snapshot
    all_edges: list[tuple[str, str, str]] = conn.execute(
        "SELECT source_id, target_id, edge_type"
        " FROM config_edges WHERE snapshot_id = ?",
        [snapshot_id],
    ).fetchall()

    # 2. Build parent map and container set from ALL edges
    parent_map = _build_parent_map(all_edges)

    # 3. resource_id → first resource_type (for edge resolution)
    all_type_rows: list[tuple[str, str]] = conn.execute(
        "SELECT resource_id, resource_type"
        " FROM config_resources WHERE snapshot_id = ?"
        " ORDER BY resource_type",  # deterministic first-type selection
        [snapshot_id],
    ).fetchall()
    rid_to_first_type: dict[str, str] = {}
    for rid, rtype in all_type_rows:
        rid_to_first_type.setdefault(rid, rtype)

    # Infer Subnet membership for resources that have only association edges to
    # a Subnet (e.g. VPC-deployed Lambda, RDS DBInstance).  Runs before VPC
    # inference so these resources land at the most specific container.
    _infer_subnet_for_residents(parent_map, all_edges, rid_to_first_type)

    # Infer VPC membership for resources (e.g. EIP) that have no containment
    # edge but are reachable from a VPC-resident resource via association edges.
    _infer_vpc_for_residents(parent_map, all_edges, rid_to_first_type)

    # Infer S3 hierarchy: place S3 AccessPoints and similar sub-resources inside
    # their parent S3 Bucket via any association edge.
    _infer_s3_hierarchy(parent_map, all_edges, rid_to_first_type)

    container_ids: set[str] = set(parent_map.values())

    # 4. Resources to display (with optional type filter)
    params: list[Any] = [snapshot_id]
    type_filter = ""
    if resource_type:
        type_filter = " AND resource_type = ?"
        params.append(resource_type)

    resource_rows: list[tuple] = conn.execute(
        f"SELECT resource_id, resource_type, resource_name, aws_region"
        f" FROM config_resources WHERE snapshot_id = ?{type_filter}"
        f" LIMIT {int(limit)}",
        params,
    ).fetchall()

    # Unique resource_ids in the displayed node set
    displayed_rids: set[str] = {r[0] for r in resource_rows}

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    # 5. Add service-group virtual nodes (only for unfiltered views)
    if not resource_type:
        # Determine which resource_ids have no physical parent in the displayed set
        svc_members: dict[str, list[tuple[str, str]]] = {}
        for row in resource_rows:
            rid, rtype = row[0], row[1]
            physical_parent = parent_map.get(rid)
            has_visible_parent = physical_parent and physical_parent in displayed_rids
            if not has_visible_parent:
                # Top-level resource → belongs to service group
                svc = _service_of(rtype)
                svc_members.setdefault(svc, []).append((rid, rtype))

        for svc_ns, members in sorted(svc_members.items()):
            svc_id = _service_node_id(svc_ns)
            svc_label = _SERVICE_LABELS.get(svc_ns, f"AWS {svc_ns}")
            nodes.append(
                {
                    "id": svc_id,
                    "type": "awsGroupNode",
                    "position": {"x": 0, "y": 0},
                    "parentId": None,
                    "data": {
                        "resource_id": svc_id,
                        "resource_type": f"__service__{svc_ns}",
                        "resource_name": svc_label,
                        "aws_region": "",
                        "is_container": True,
                        "member_count": len(members),
                    },
                }
            )

    # 6. Build leaf + container resource nodes
    for row in resource_rows:
        rid, rtype = row[0], row[1]
        physical_parent = parent_map.get(rid)

        parent_id: str | None = None
        if physical_parent and physical_parent in displayed_rids:
            # Physical containment edge resolved to a visible node
            parent_id = physical_parent
        elif not resource_type:
            # No physical parent → service group parent
            svc = _service_of(rtype)
            parent_id = _service_node_id(svc)

        nodes.append(
            {
                "id": rid,
                "type": "awsGroupNode" if rid in container_ids else "awsNode",
                "position": {"x": 0, "y": 0},
                "parentId": parent_id,
                "data": {
                    "resource_id": rid,
                    "resource_type": rtype,
                    "resource_name": row[2],
                    "aws_region": row[3],
                    "is_container": rid in container_ids,
                },
            }
        )

    # 7. Non-containment edges (only between displayed nodes)
    for src_id, tgt_id, etype in all_edges:
        n = etype.strip().lower()
        if n.startswith("contains") or n.startswith("is contained in"):
            continue
        if src_id in displayed_rids and tgt_id in displayed_rids:
            edges.append(
                {
                    "id": f"{src_id}__{tgt_id}__{etype}",
                    "source": src_id,
                    "target": tgt_id,
                    "label": etype,
                }
            )

    # 8. Compute nesting depth for each node (0 = root / service-group level).
    # Used by the frontend to apply depth-aware visual styling.
    id_to_parent_id: dict[str, str | None] = {n["id"]: n["parentId"] for n in nodes}
    depth_of: dict[str, int] = {}
    for nid, pid in id_to_parent_id.items():
        if pid is None:
            depth_of[nid] = 0
    changed = True
    while changed:
        changed = False
        for nid, pid in id_to_parent_id.items():
            if nid not in depth_of and pid is not None and pid in depth_of:
                depth_of[nid] = depth_of[pid] + 1
                changed = True
    for node in nodes:
        node["data"]["depth"] = depth_of.get(node["id"], 0)

    return {"nodes": nodes, "edges": edges}


def get_resource_detail(
    conn: duckdb.DuckDBPyConnection,
    snapshot_id: str,
    resource_id: str,
    resource_type: str | None = None,
) -> dict[str, Any] | None:
    """Return full detail for a single resource.

    When *resource_type* is supplied the lookup is exact
    (``resource_id`` + ``resource_type``).  Otherwise the first row
    matching ``resource_id`` is returned.
    """
    if resource_type:
        row = conn.execute(
            "SELECT resource_id, snapshot_id, resource_type, aws_region,"
            " resource_name, configuration, tags"
            " FROM config_resources"
            " WHERE snapshot_id = ? AND resource_id = ? AND resource_type = ? LIMIT 1",
            [snapshot_id, resource_id, resource_type],
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT resource_id, snapshot_id, resource_type, aws_region,"
            " resource_name, configuration, tags"
            " FROM config_resources"
            " WHERE snapshot_id = ? AND resource_id = ? LIMIT 1",
            [snapshot_id, resource_id],
        ).fetchone()
    if row is None:
        return None
    return {
        "resource_id": row[0],
        "snapshot_id": row[1],
        "resource_type": row[2],
        "aws_region": row[3],
        "resource_name": row[4],
        "configuration": json.loads(row[5]) if row[5] else None,
        "tags": json.loads(row[6]) if row[6] else None,
    }
