"""Shared pytest fixtures for config_viz backend tests.

Each test that needs a database gets a fresh temporary DuckDB file so
tests remain fully isolated.
"""

import duckdb
import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

_CREATE_TABLES_SQL = [
    """
    CREATE TABLE IF NOT EXISTS config_snapshots (
        snapshot_id  VARCHAR PRIMARY KEY,
        account_id   VARCHAR,
        aws_region   VARCHAR,
        captured_at  TIMESTAMP,
        source_path  VARCHAR,
        record_count INTEGER
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS config_resources (
        resource_id   VARCHAR,
        snapshot_id   VARCHAR,
        resource_type VARCHAR,
        aws_region    VARCHAR,
        resource_name VARCHAR,
        configuration VARCHAR,
        tags          VARCHAR,
        PRIMARY KEY (resource_id, resource_type, snapshot_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS config_edges (
        snapshot_id VARCHAR,
        source_id   VARCHAR,
        target_id   VARCHAR,
        edge_type   VARCHAR,
        PRIMARY KEY (snapshot_id, source_id, target_id, edge_type)
    )
    """,
]


def _create_tables(conn: duckdb.DuckDBPyConnection) -> None:
    """Execute all CREATE TABLE statements on *conn*."""
    for ddl in _CREATE_TABLES_SQL:
        conn.execute(ddl)


def _seed(conn: duckdb.DuckDBPyConnection) -> None:
    """Insert mini snapshot data: snap-001, 2 resources, 1 edge."""
    conn.execute("""
        INSERT INTO config_snapshots VALUES
            ('snap-001', '123456789012', 'ap-northeast-1',
             TIMESTAMP '2026-01-01 00:00:00', '/data/snap.json', 2)
        """)
    conn.execute("""
        INSERT INTO config_resources VALUES
            ('i-12345', 'snap-001', 'AWS::EC2::Instance',
             'ap-northeast-1', 'web-server',
             '{"instanceType":"t3.micro"}', '{"Name":"web-server"}'),
            ('sg-aaaa', 'snap-001', 'AWS::EC2::SecurityGroup',
             'ap-northeast-1', 'web-sg',
             '{"groupId":"sg-aaaa"}', NULL)
        """)
    conn.execute("""
        INSERT INTO config_edges VALUES
            ('snap-001', 'i-12345', 'sg-aaaa', 'Is associated with')
        """)


# ---------------------------------------------------------------------------
# DB fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db_empty(tmp_path) -> str:
    """Temporary DuckDB with empty config tables."""
    path = str(tmp_path / "empty.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    conn.close()
    return path


@pytest.fixture
def tmp_db_seeded(tmp_path) -> str:
    """Temporary DuckDB seeded with snap-001 (2 resources, 1 edge)."""
    path = str(tmp_path / "seeded.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    _seed(conn)
    conn.close()
    return path


# ---------------------------------------------------------------------------
# TestClient fixtures
# ---------------------------------------------------------------------------


def _seed_vpc_full(conn: duckdb.DuckDBPyConnection) -> None:
    """Insert VPC-full snapshot: snap-003 with realistic VPC-resident resources.

    Resources
    ---------
    vpc-200    AWS::EC2::VPC          (root — no parent)
    subnet-200 AWS::EC2::Subnet       ("Is contained in Vpc" → vpc-200)
    rtb-200    AWS::EC2::RouteTable   ("Is contained in Vpc" → vpc-200)
    nat-200    AWS::EC2::NatGateway   ("Is contained in Subnet" → subnet-200)
    i-200      AWS::EC2::Instance     ("Is contained in Subnet" → subnet-200)
    eip-200    AWS::EC2::EIP          ("Is associated with" → nat-200, NO containment edge)

    Design intent
    -------------
    eip-200 has NO containment edge at all.  The inference logic should walk
    the association edge eip-200 → nat-200, find nat-200's VPC ancestor
    (vpc-200 via subnet-200), and set eip-200.parent = vpc-200.
    """
    conn.execute("""
        INSERT INTO config_snapshots VALUES
            ('snap-003', '999988887777', 'ap-northeast-1',
             TIMESTAMP '2026-05-10 00:00:00', '/data/snap3.json', 6)
        """)
    conn.execute("""
        INSERT INTO config_resources VALUES
            ('vpc-200',    'snap-003', 'AWS::EC2::VPC',
             'ap-northeast-1', 'prod-vpc',     '{"vpcId":"vpc-200"}',         NULL),
            ('subnet-200', 'snap-003', 'AWS::EC2::Subnet',
             'ap-northeast-1', 'public-sub',   '{"subnetId":"subnet-200"}',   NULL),
            ('rtb-200',    'snap-003', 'AWS::EC2::RouteTable',
             'ap-northeast-1', 'main-rtb',     '{"routeTableId":"rtb-200"}',  NULL),
            ('nat-200',    'snap-003', 'AWS::EC2::NatGateway',
             'ap-northeast-1', 'prod-nat',     '{"natGatewayId":"nat-200"}',  NULL),
            ('i-200',      'snap-003', 'AWS::EC2::Instance',
             'ap-northeast-1', 'app-server',   '{"instanceType":"t3.small"}', NULL),
            ('eip-200',    'snap-003', 'AWS::EC2::EIP',
             'ap-northeast-1', 'prod-eip',     '{"allocationId":"eip-200"}',  NULL)
        """)
    conn.execute("""
        INSERT INTO config_edges VALUES
            ('snap-003', 'subnet-200', 'vpc-200',    'Is contained in Vpc'),
            ('snap-003', 'rtb-200',    'vpc-200',    'Is contained in Vpc'),
            ('snap-003', 'nat-200',    'subnet-200', 'Is contained in Subnet'),
            ('snap-003', 'i-200',      'subnet-200', 'Is contained in Subnet'),
            ('snap-003', 'eip-200',    'nat-200',    'Is associated with')
        """)


def _seed_hierarchy(conn: duckdb.DuckDBPyConnection) -> None:
    """Insert hierarchy snapshot: snap-002 with VPC → Subnet → EC2 containment.

    Resources
    ---------
    vpc-001    AWS::EC2::VPC         (root — no parent)
    subnet-001 AWS::EC2::Subnet      (contained in vpc-001)
    i-001      AWS::EC2::Instance    (contained in subnet-001)
    sg-001     AWS::EC2::SecurityGroup (NOT a container — associated with i-001)

    Edges  — uses real AWS Config edge-type strings (partial-match format)
    -----------------------------------------
    vpc-001    → subnet-001   "Contains Subnet"
    subnet-001 → i-001        "Contains"
    i-001      → sg-001       "Is associated with"
    """
    conn.execute("""
        INSERT INTO config_snapshots VALUES
            ('snap-002', '111122223333', 'ap-northeast-1',
             TIMESTAMP '2026-05-01 00:00:00', '/data/snap2.json', 4)
        """)
    conn.execute("""
        INSERT INTO config_resources VALUES
            ('vpc-001',    'snap-002', 'AWS::EC2::VPC',
             'ap-northeast-1', 'main-vpc',    '{"vpcId":"vpc-001"}',    NULL),
            ('subnet-001', 'snap-002', 'AWS::EC2::Subnet',
             'ap-northeast-1', 'public-sub',  '{"subnetId":"subnet-001"}', NULL),
            ('i-001',      'snap-002', 'AWS::EC2::Instance',
             'ap-northeast-1', 'app-server',  '{"instanceType":"t3.small"}', NULL),
            ('sg-001',     'snap-002', 'AWS::EC2::SecurityGroup',
             'ap-northeast-1', 'app-sg',      '{"groupId":"sg-001"}',  NULL)
        """)
    conn.execute("""
        INSERT INTO config_edges VALUES
            ('snap-002', 'vpc-001',    'subnet-001', 'Contains Subnet'),
            ('snap-002', 'subnet-001', 'i-001',      'Contains'),
            ('snap-002', 'i-001',      'sg-001',     'Is associated with')
        """)


def _make_override(db_path: str):
    """Return a FastAPI dependency override that opens *db_path* READ_ONLY."""

    def override_conn():
        conn = duckdb.connect(db_path, read_only=True)
        try:
            yield conn
        finally:
            conn.close()

    return override_conn


@pytest.fixture
def tmp_db_hierarchy(tmp_path) -> str:
    """Temporary DuckDB seeded with snap-002 (VPC → Subnet → EC2 hierarchy)."""
    path = str(tmp_path / "hierarchy.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    _seed_hierarchy(conn)
    conn.close()
    return path


@pytest.fixture
def tmp_db_vpc_full(tmp_path) -> str:
    """Temporary DuckDB seeded with snap-003 (VPC + Subnet/RouteTable/NatGW/Instance/EIP)."""
    path = str(tmp_path / "vpc_full.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    _seed_vpc_full(conn)
    conn.close()
    return path


@pytest.fixture
def client_hierarchy(tmp_db_hierarchy):
    """TestClient backed by the hierarchy DB (snap-002, 4 resources, 3 edges)."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_hierarchy)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_vpc_full(tmp_db_vpc_full):
    """TestClient backed by the vpc-full DB (snap-003, 6 resources including EIP)."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_vpc_full)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_empty(tmp_db_empty):
    """TestClient backed by an empty config DB."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_empty)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_seeded(tmp_db_seeded):
    """TestClient backed by snap-001 (2 resources: Instance + SecurityGroup, 1 edge)."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_seeded)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# HG-1/HG-2: VPC-extended snapshot (snap-004)
# NetworkAcl (containment), NetworkInterface (containment), Lambda/RDS (association),
# ALB (association-only to VPC)
# ---------------------------------------------------------------------------


def _seed_vpc_extended(conn: duckdb.DuckDBPyConnection) -> None:
    """Insert snap-004: VPC with NetworkAcl, NetworkInterface, Lambda, RDS, ALB.

    Resources
    ---------
    vpc-400    AWS::EC2::VPC
    subnet-400 AWS::EC2::Subnet            (Is contained in Vpc → vpc-400)
    acl-400    AWS::EC2::NetworkAcl        (Is contained in Vpc → vpc-400)
    eni-400    AWS::EC2::NetworkInterface  (Is contained in Subnet → subnet-400)
    lambda-400 AWS::Lambda::Function       (Is associated with → subnet-400, no containment)
    rds-400    AWS::RDS::DBInstance        (Is associated with → subnet-400, no containment)
    alb-400    AWS::ElasticLoadBalancingV2::LoadBalancer  (Is associated with → vpc-400, no containment)

    Design intent
    -------------
    * acl-400 / eni-400 use explicit containment edges.
    * lambda-400 / rds-400 must be inferred into subnet-400 via subnet inference.
    * alb-400 must be inferred into vpc-400 via VPC inference (extended VPC_RESIDENT_TYPES).
    """
    conn.execute("""
        INSERT INTO config_snapshots VALUES
            ('snap-004', '111122223333', 'ap-northeast-1',
             TIMESTAMP '2026-05-15 00:00:00', '/data/snap4.json', 7)
        """)
    conn.execute("""
        INSERT INTO config_resources VALUES
            ('vpc-400',    'snap-004', 'AWS::EC2::VPC',
             'ap-northeast-1', 'ext-vpc',    '{"vpcId":"vpc-400"}',                       NULL),
            ('subnet-400', 'snap-004', 'AWS::EC2::Subnet',
             'ap-northeast-1', 'ext-sub',    '{"subnetId":"subnet-400"}',                 NULL),
            ('acl-400',    'snap-004', 'AWS::EC2::NetworkAcl',
             'ap-northeast-1', 'ext-acl',    '{"networkAclId":"acl-400"}',                NULL),
            ('eni-400',    'snap-004', 'AWS::EC2::NetworkInterface',
             'ap-northeast-1', 'ext-eni',    '{"networkInterfaceId":"eni-400"}',           NULL),
            ('lambda-400', 'snap-004', 'AWS::Lambda::Function',
             'ap-northeast-1', 'ext-lambda', '{"functionName":"ext-lambda"}',             NULL),
            ('rds-400',    'snap-004', 'AWS::RDS::DBInstance',
             'ap-northeast-1', 'ext-rds',    '{"dbInstanceIdentifier":"rds-400"}',        NULL),
            ('alb-400',    'snap-004', 'AWS::ElasticLoadBalancingV2::LoadBalancer',
             'ap-northeast-1', 'ext-alb',    '{"loadBalancerName":"ext-alb"}',            NULL)
        """)
    conn.execute("""
        INSERT INTO config_edges VALUES
            ('snap-004', 'subnet-400', 'vpc-400',    'Is contained in Vpc'),
            ('snap-004', 'acl-400',    'vpc-400',    'Is contained in Vpc'),
            ('snap-004', 'eni-400',    'subnet-400', 'Is contained in Subnet'),
            ('snap-004', 'lambda-400', 'subnet-400', 'Is associated with'),
            ('snap-004', 'rds-400',    'subnet-400', 'Is associated with'),
            ('snap-004', 'alb-400',    'vpc-400',    'Is associated with')
        """)


# ---------------------------------------------------------------------------
# HG-3: Auto Scaling Group hierarchy (snap-005)
# ---------------------------------------------------------------------------


def _seed_asg_hierarchy(conn: duckdb.DuckDBPyConnection) -> None:
    """Insert snap-005: AutoScalingGroup → EC2 Instance.

    Resources
    ---------
    asg-500  AWS::AutoScaling::AutoScalingGroup
    i-500    AWS::EC2::Instance  (Is member of AutoScalingGroup → asg-500)

    Design intent
    -------------
    The 'Is member of AutoScalingGroup' edge must be treated as containment
    so that i-500 is placed inside the asg-500 group node.
    """
    conn.execute("""
        INSERT INTO config_snapshots VALUES
            ('snap-005', '111122223333', 'ap-northeast-1',
             TIMESTAMP '2026-05-15 00:00:00', '/data/snap5.json', 2)
        """)
    conn.execute("""
        INSERT INTO config_resources VALUES
            ('asg-500', 'snap-005', 'AWS::AutoScaling::AutoScalingGroup',
             'ap-northeast-1', 'my-asg',  '{"autoScalingGroupName":"my-asg"}', NULL),
            ('i-500',   'snap-005', 'AWS::EC2::Instance',
             'ap-northeast-1', 'asg-ec2', '{"instanceType":"t3.small"}',       NULL)
        """)
    conn.execute("""
        INSERT INTO config_edges VALUES
            ('snap-005', 'i-500', 'asg-500', 'Is member of AutoScalingGroup')
        """)


# ---------------------------------------------------------------------------
# HG-4: CloudFormation Stack grouping (snap-006)
# ---------------------------------------------------------------------------


def _seed_cfn_stack(conn: duckdb.DuckDBPyConnection) -> None:
    """Insert snap-006: CloudFormation Stack containing Instance + nested Stack.

    Resources
    ---------
    stack-600   AWS::CloudFormation::Stack  (root)
    i-600       AWS::EC2::Instance          (Contains → stack-600)
    nstack-600  AWS::CloudFormation::Stack  (nested, Contains → stack-600)

    Design intent
    -------------
    Both i-600 and nstack-600 must be placed inside stack-600 via the generic
    'Contains' edge already handled by _build_parent_map (no prod code change).
    """
    conn.execute("""
        INSERT INTO config_snapshots VALUES
            ('snap-006', '111122223333', 'ap-northeast-1',
             TIMESTAMP '2026-05-15 00:00:00', '/data/snap6.json', 3)
        """)
    conn.execute("""
        INSERT INTO config_resources VALUES
            ('stack-600',  'snap-006', 'AWS::CloudFormation::Stack',
             'ap-northeast-1', 'parent-stack', '{"stackId":"stack-600"}',  NULL),
            ('i-600',      'snap-006', 'AWS::EC2::Instance',
             'ap-northeast-1', 'cfn-ec2',      '{"instanceType":"t3.micro"}', NULL),
            ('nstack-600', 'snap-006', 'AWS::CloudFormation::Stack',
             'ap-northeast-1', 'nested-stack', '{"stackId":"nstack-600"}', NULL)
        """)
    conn.execute("""
        INSERT INTO config_edges VALUES
            ('snap-006', 'stack-600', 'i-600',      'Contains'),
            ('snap-006', 'stack-600', 'nstack-600', 'Contains')
        """)


# ---------------------------------------------------------------------------
# HG-5: RDS Cluster → DB Instance (snap-007)
# ---------------------------------------------------------------------------


def _seed_rds_cluster(conn: duckdb.DuckDBPyConnection) -> None:
    """Insert snap-007: RDS DBCluster containing a DBInstance.

    Resources
    ---------
    cluster-700  AWS::RDS::DBCluster
    db-700       AWS::RDS::DBInstance  (Contains DBInstance ← cluster-700)

    Design intent
    -------------
    'Contains DBInstance' is already handled by _build_parent_map's
    startswith('contains') partial match.
    """
    conn.execute("""
        INSERT INTO config_snapshots VALUES
            ('snap-007', '111122223333', 'ap-northeast-1',
             TIMESTAMP '2026-05-15 00:00:00', '/data/snap7.json', 2)
        """)
    conn.execute("""
        INSERT INTO config_resources VALUES
            ('cluster-700', 'snap-007', 'AWS::RDS::DBCluster',
             'ap-northeast-1', 'aurora-cluster', '{"dbClusterIdentifier":"cluster-700"}', NULL),
            ('db-700',      'snap-007', 'AWS::RDS::DBInstance',
             'ap-northeast-1', 'aurora-db',      '{"dbInstanceIdentifier":"db-700"}',    NULL)
        """)
    conn.execute("""
        INSERT INTO config_edges VALUES
            ('snap-007', 'cluster-700', 'db-700', 'Contains DBInstance')
        """)


# ---------------------------------------------------------------------------
# HG-6: ECS Cluster → Service (snap-008)
# ---------------------------------------------------------------------------


def _seed_ecs_cluster(conn: duckdb.DuckDBPyConnection) -> None:
    """Insert snap-008: ECS Cluster containing an ECS Service.

    Resources
    ---------
    ecs-800  AWS::ECS::Cluster
    svc-800  AWS::ECS::Service  (Contains ← ecs-800)

    Design intent
    -------------
    'Contains' edge is already handled by _build_parent_map.
    """
    conn.execute("""
        INSERT INTO config_snapshots VALUES
            ('snap-008', '111122223333', 'ap-northeast-1',
             TIMESTAMP '2026-05-15 00:00:00', '/data/snap8.json', 2)
        """)
    conn.execute("""
        INSERT INTO config_resources VALUES
            ('ecs-800', 'snap-008', 'AWS::ECS::Cluster',
             'ap-northeast-1', 'my-cluster', '{"clusterName":"my-cluster"}',  NULL),
            ('svc-800', 'snap-008', 'AWS::ECS::Service',
             'ap-northeast-1', 'my-service', '{"serviceName":"my-service"}',  NULL)
        """)
    conn.execute("""
        INSERT INTO config_edges VALUES
            ('snap-008', 'ecs-800', 'svc-800', 'Contains')
        """)


# ---------------------------------------------------------------------------
# DB fixtures — HG phases
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db_vpc_extended(tmp_path) -> str:
    """Temporary DuckDB seeded with snap-004 (VPC + extended resource types)."""
    path = str(tmp_path / "vpc_extended.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    _seed_vpc_extended(conn)
    conn.close()
    return path


@pytest.fixture
def tmp_db_asg(tmp_path) -> str:
    """Temporary DuckDB seeded with snap-005 (ASG → Instance)."""
    path = str(tmp_path / "asg.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    _seed_asg_hierarchy(conn)
    conn.close()
    return path


@pytest.fixture
def tmp_db_cfn(tmp_path) -> str:
    """Temporary DuckDB seeded with snap-006 (CloudFormation Stack)."""
    path = str(tmp_path / "cfn.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    _seed_cfn_stack(conn)
    conn.close()
    return path


@pytest.fixture
def tmp_db_rds_cluster(tmp_path) -> str:
    """Temporary DuckDB seeded with snap-007 (RDS Cluster → DBInstance)."""
    path = str(tmp_path / "rds_cluster.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    _seed_rds_cluster(conn)
    conn.close()
    return path


@pytest.fixture
def tmp_db_ecs(tmp_path) -> str:
    """Temporary DuckDB seeded with snap-008 (ECS Cluster → Service)."""
    path = str(tmp_path / "ecs.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    _seed_ecs_cluster(conn)
    conn.close()
    return path


# ---------------------------------------------------------------------------
# TestClient fixtures — HG phases
# ---------------------------------------------------------------------------


@pytest.fixture
def client_vpc_extended(tmp_db_vpc_extended):
    """TestClient backed by snap-004 (VPC + extended resource types)."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_vpc_extended)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_asg(tmp_db_asg):
    """TestClient backed by snap-005 (ASG hierarchy)."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_asg)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_cfn(tmp_db_cfn):
    """TestClient backed by snap-006 (CloudFormation Stack hierarchy)."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_cfn)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_rds_cluster(tmp_db_rds_cluster):
    """TestClient backed by snap-007 (RDS Cluster → DBInstance)."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_rds_cluster)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def client_ecs(tmp_db_ecs):
    """TestClient backed by snap-008 (ECS Cluster → Service)."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_ecs)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# BA-23: S3 Bucket hierarchy (snap-009)
# ---------------------------------------------------------------------------


def _seed_s3_hierarchy(conn: duckdb.DuckDBPyConnection) -> None:
    """Insert snap-009: S3 Bucket containing an AccessPoint via association edge.

    Resources
    ---------
    s3-bucket-001  AWS::S3::Bucket
    s3-ap-001      AWS::S3::AccessPoint  (no containment edge; only association)

    Design intent
    -------------
    AWS Config does not emit a 'Contains' edge for S3 AccessPoints.  Instead it
    emits 'Is associated with bucket' (or similar association).  The
    _infer_s3_hierarchy() function must detect this and place the AccessPoint
    inside its parent Bucket.
    """
    conn.execute("""
        INSERT INTO config_snapshots VALUES
            ('snap-009', '111122223333', 'ap-northeast-1',
             TIMESTAMP '2026-05-20 00:00:00', '/data/snap9.json', 2)
        """)
    conn.execute("""
        INSERT INTO config_resources VALUES
            ('s3-bucket-001', 'snap-009', 'AWS::S3::Bucket',
             'ap-northeast-1', 'my-bucket',
             '{"bucketName":"my-bucket"}', NULL),
            ('s3-ap-001',     'snap-009', 'AWS::S3::AccessPoint',
             'ap-northeast-1', 'my-access-point',
             '{"name":"my-access-point"}', NULL)
        """)
    conn.execute("""
        INSERT INTO config_edges VALUES
            ('snap-009', 's3-ap-001', 's3-bucket-001', 'Is associated with bucket')
        """)


@pytest.fixture
def tmp_db_s3(tmp_path) -> str:
    """Temporary DuckDB seeded with snap-009 (S3 Bucket + AccessPoint)."""
    path = str(tmp_path / "s3.db")
    conn = duckdb.connect(path)
    _create_tables(conn)
    _seed_s3_hierarchy(conn)
    conn.close()
    return path


@pytest.fixture
def client_s3(tmp_db_s3):
    """TestClient backed by snap-009 (S3 Bucket hierachy)."""
    from backend.db import get_conn
    from backend.main import app

    app.dependency_overrides[get_conn] = _make_override(tmp_db_s3)
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
