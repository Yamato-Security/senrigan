"""Phase A backend tests — BA-01 to BA-14.

All tests follow the TDD Red-Green-Refactor cycle:
  Red   : written here before any implementation exists.
  Green : backend/ modules are added to make each test pass.
"""

import pytest

# ---------------------------------------------------------------------------
# BA-01: Empty DB → GET /api/snapshots returns []
# ---------------------------------------------------------------------------


def test_ba01_empty_db_snapshots_returns_empty_list(client_empty):
    response = client_empty.get("/api/snapshots")
    assert response.status_code == 200
    assert response.json() == []


# ---------------------------------------------------------------------------
# BA-02: One ingested snapshot → /api/snapshots returns exactly 1 item
# ---------------------------------------------------------------------------


def test_ba02_one_snapshot_returns_one_item(client_seeded):
    response = client_seeded.get("/api/snapshots")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["snapshot_id"] == "snap-001"
    assert data[0]["account_id"] == "123456789012"
    assert data[0]["aws_region"] == "ap-northeast-1"
    assert data[0]["record_count"] == 2


# ---------------------------------------------------------------------------
# BA-03: /api/snapshots/{id}/resource-types returns the correct type list
# ---------------------------------------------------------------------------


def test_ba03_resource_types_returns_correct_list(client_seeded):
    response = client_seeded.get("/api/snapshots/snap-001/resource-types")
    assert response.status_code == 200
    types = response.json()
    assert isinstance(types, list)
    assert "AWS::EC2::Instance" in types
    assert "AWS::EC2::SecurityGroup" in types


# ---------------------------------------------------------------------------
# BA-04: /api/snapshots/{id}/graph — node count matches resource count
# ---------------------------------------------------------------------------


def test_ba04_graph_node_count_matches_resources(client_seeded):
    response = client_seeded.get("/api/snapshots/snap-001/graph")
    assert response.status_code == 200
    data = response.json()
    assert "nodes" in data
    assert "edges" in data
    # 2 physical resources + 1 EC2 service-group virtual node = 3 total
    assert len(data["nodes"]) == 3
    node_ids = {n["id"] for n in data["nodes"]}
    assert "i-12345" in node_ids
    assert "sg-aaaa" in node_ids
    assert "__svc__EC2" in node_ids


# ---------------------------------------------------------------------------
# BA-05: /api/snapshots/{id}/graph — edges exclude dangling references
# ---------------------------------------------------------------------------


def test_ba05_graph_edges_exclude_dangling(client_seeded):
    response = client_seeded.get("/api/snapshots/snap-001/graph")
    assert response.status_code == 200
    data = response.json()
    edges = data["edges"]
    # snap-001 has exactly 1 intra-snapshot edge (i-12345 → sg-aaaa)
    assert len(edges) == 1
    assert edges[0]["source"] == "i-12345"
    assert edges[0]["target"] == "sg-aaaa"
    assert edges[0]["label"] == "Is associated with"


# ---------------------------------------------------------------------------
# BA-06: /api/snapshots/{id}/resources/{rid} returns configuration + tags
# ---------------------------------------------------------------------------


def test_ba06_resource_detail_returns_configuration_and_tags(client_seeded):
    response = client_seeded.get("/api/snapshots/snap-001/resources/i-12345")
    assert response.status_code == 200
    data = response.json()
    assert data["resource_id"] == "i-12345"
    assert data["resource_type"] == "AWS::EC2::Instance"
    # configuration is returned as a parsed JSON object
    assert isinstance(data["configuration"], dict)
    assert data["configuration"]["instanceType"] == "t3.micro"
    # tags is a non-null dict for i-12345
    assert isinstance(data["tags"], dict)
    assert data["tags"]["Name"] == "web-server"


def test_ba06_resource_detail_null_tags_returns_none(client_seeded):
    # sg-aaaa was seeded with NULL tags
    response = client_seeded.get("/api/snapshots/snap-001/resources/sg-aaaa")
    assert response.status_code == 200
    data = response.json()
    assert data["resource_id"] == "sg-aaaa"
    assert data["tags"] is None


# ---------------------------------------------------------------------------
# BA-07: Non-existent snapshot_id returns 404 on all relevant endpoints
# ---------------------------------------------------------------------------


def test_ba07_nonexistent_snapshot_resource_types_returns_404(client_seeded):
    response = client_seeded.get("/api/snapshots/no-such-snap/resource-types")
    assert response.status_code == 404


def test_ba07_nonexistent_snapshot_graph_returns_404(client_seeded):
    response = client_seeded.get("/api/snapshots/no-such-snap/graph")
    assert response.status_code == 404


def test_ba07_nonexistent_snapshot_resource_detail_returns_404(client_seeded):
    response = client_seeded.get("/api/snapshots/no-such-snap/resources/i-12345")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# BA-08: resource_type= query param filters graph nodes
# ---------------------------------------------------------------------------


def test_ba08_resource_type_filter_applies_to_graph_nodes(client_seeded):
    response = client_seeded.get(
        "/api/snapshots/snap-001/graph?resource_type=AWS::EC2::Instance"
    )
    assert response.status_code == 200
    data = response.json()
    # Filtered view: no service-group virtual nodes, only 1 physical resource
    assert len(data["nodes"]) == 1
    assert data["nodes"][0]["id"] == "i-12345"
    assert data["nodes"][0]["data"]["resource_type"] == "AWS::EC2::Instance"


def test_ba08_resource_type_filter_excludes_cross_type_edges(client_seeded):
    # When filtering to only Instance nodes, the edge to sg-aaaa (SecurityGroup)
    # disappears because sg-aaaa is not in the filtered node set.
    response = client_seeded.get(
        "/api/snapshots/snap-001/graph?resource_type=AWS::EC2::Instance"
    )
    assert response.status_code == 200
    data = response.json()
    # sg-aaaa is outside the filtered set → edge must be excluded
    assert len(data["edges"]) == 0


# ---------------------------------------------------------------------------
# BA-09: limit= query param caps the number of returned nodes
# ---------------------------------------------------------------------------


def test_ba09_limit_caps_node_count(client_seeded):
    response = client_seeded.get("/api/snapshots/snap-001/graph?limit=1")
    assert response.status_code == 200
    data = response.json()
    # limit caps physical resource nodes; service-group virtual nodes are always added
    physical = [n for n in data["nodes"] if not n["id"].startswith("__svc__")]
    assert len(physical) <= 1


# ---------------------------------------------------------------------------
# BA-10: validate_sql rejects write / DDL keywords (READ_ONLY blocklist)
# ---------------------------------------------------------------------------


def test_ba10_blocklist_rejects_drop(client_seeded):
    from backend.query import QueryValidationError, validate_sql

    with pytest.raises(QueryValidationError, match="not allowed"):
        validate_sql("DROP TABLE config_snapshots")


def test_ba10_blocklist_rejects_insert(client_seeded):
    from backend.query import QueryValidationError, validate_sql

    with pytest.raises(QueryValidationError, match="not allowed"):
        validate_sql(
            "INSERT INTO config_snapshots VALUES ('x', null, null, null, null, 0)"
        )


def test_ba10_blocklist_rejects_delete(client_seeded):
    from backend.query import QueryValidationError, validate_sql

    with pytest.raises(QueryValidationError, match="not allowed"):
        validate_sql("DELETE FROM config_resources")


def test_ba10_blocklist_rejects_create(client_seeded):
    from backend.query import QueryValidationError, validate_sql

    with pytest.raises(QueryValidationError, match="not allowed"):
        validate_sql("CREATE TABLE evil (x VARCHAR)")


def test_ba10_blocklist_allows_select(client_seeded):
    from backend.query import validate_sql

    # Must NOT raise — plain SELECT is allowed
    validate_sql("SELECT * FROM config_snapshots")


# ---------------------------------------------------------------------------
# BA-11: Hierarchy — graph nodes carry parentId and is_container metadata
# ---------------------------------------------------------------------------


def test_ba11_vpc_node_has_no_parent(client_hierarchy):
    """Root container (VPC) must be placed inside the EC2 service-group node."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    # With service groups, VPC is inside __svc__EC2, not at the root
    assert nodes["vpc-001"]["parentId"] == "__svc__EC2"


def test_ba11_subnet_node_parent_is_vpc(client_hierarchy):
    """Subnet node parentId must equal its containing VPC."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["subnet-001"]["parentId"] == "vpc-001"


def test_ba11_instance_node_parent_is_subnet(client_hierarchy):
    """EC2 Instance node parentId must equal its containing Subnet."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["i-001"]["parentId"] == "subnet-001"


def test_ba11_vpc_and_subnet_flagged_as_containers(client_hierarchy):
    """VPC and Subnet must have is_container=True; Instance and SG must be False."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["vpc-001"]["data"]["is_container"] is True
    assert nodes["subnet-001"]["data"]["is_container"] is True
    assert nodes["i-001"]["data"]["is_container"] is False
    assert nodes["sg-001"]["data"]["is_container"] is False


def test_ba11_container_nodes_use_awsGroupNode_type(client_hierarchy):
    """Container nodes must have type='awsGroupNode'; leaves must be 'awsNode'."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["vpc-001"]["type"] == "awsGroupNode"
    assert nodes["subnet-001"]["type"] == "awsGroupNode"
    assert nodes["i-001"]["type"] == "awsNode"
    assert nodes["sg-001"]["type"] == "awsNode"


def test_ba11_contains_edges_excluded_from_edge_list(client_hierarchy):
    """'Contains' edges must NOT appear in the edges list (expressed via parentId)."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    data = response.json()
    labels = [e["label"] for e in data["edges"]]
    assert "Contains" not in labels, "containment edges must be removed from edge list"


def test_ba11_association_edge_still_present(client_hierarchy):
    """Non-containment edges ('Is associated with') must remain in the edge list."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    data = response.json()
    labels = [e["label"] for e in data["edges"]]
    assert "Is associated with" in labels


def test_ba11_parent_outside_filtered_set_is_null(client_hierarchy):
    """When resource_type filter excludes the parent, parentId must be None."""
    # Filter to only EC2::Instance; its parent (Subnet) is excluded
    response = client_hierarchy.get(
        "/api/snapshots/snap-002/graph?resource_type=AWS::EC2::Instance"
    )
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert (
        nodes["i-001"]["parentId"] is None
    ), "parent (subnet-001) is not in the filtered set, so parentId must be None"


# ---------------------------------------------------------------------------
# BA-12: config_snapshots table missing → /api/snapshots returns [] (not 500)
#
# This covers the case where config-import has never been run.
# The cloudtrail_events table exists but the Config tables do not.
# ---------------------------------------------------------------------------


@pytest.fixture
def client_no_config_tables(tmp_path):
    """TestClient backed by a DB that has NO config_* tables (only CloudTrail)."""
    import duckdb
    from fastapi.testclient import TestClient
    from backend.db import get_conn
    from backend.main import app

    db_path = str(tmp_path / "no_config.db")
    conn = duckdb.connect(db_path)
    # Only create the cloudtrail table — config tables are intentionally absent
    conn.execute(
        "CREATE TABLE cloudtrail_events (event_time TIMESTAMP, event_name VARCHAR)"
    )
    conn.close()

    def override_conn():
        c = duckdb.connect(db_path, read_only=True)
        try:
            yield c
        finally:
            c.close()

    app.dependency_overrides[get_conn] = override_conn
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def test_ba12_no_config_tables_snapshots_returns_empty_list(client_no_config_tables):
    """GET /api/snapshots returns 200 [] when config_snapshots table does not exist."""
    response = client_no_config_tables.get("/api/snapshots")
    assert response.status_code == 200
    assert response.json() == []


def test_ba12_no_config_tables_snapshot_id_returns_404(client_no_config_tables):
    """GET /api/snapshots/{id}/resource-types returns 404 when tables don't exist."""
    response = client_no_config_tables.get("/api/snapshots/snap-xxx/resource-types")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# BA-13: Service-group virtual nodes — full (unfiltered) graph response
# ---------------------------------------------------------------------------


def test_ba13_service_group_node_present_in_full_graph(client_seeded):
    """Full graph must include a service-group virtual node for EC2."""
    response = client_seeded.get("/api/snapshots/snap-001/graph")
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert "__svc__EC2" in nodes, "EC2 service-group node must be present"
    svc = nodes["__svc__EC2"]
    assert svc["type"] == "awsGroupNode"
    assert svc["parentId"] is None
    assert svc["data"]["is_container"] is True


def test_ba13_physical_resources_have_service_group_as_parent(client_seeded):
    """i-12345 and sg-aaaa must both have __svc__EC2 as parentId."""
    response = client_seeded.get("/api/snapshots/snap-001/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["i-12345"]["parentId"] == "__svc__EC2"
    assert nodes["sg-aaaa"]["parentId"] == "__svc__EC2"


def test_ba13_service_group_absent_in_filtered_view(client_seeded):
    """Filtered view must NOT include service-group virtual nodes."""
    response = client_seeded.get(
        "/api/snapshots/snap-001/graph?resource_type=AWS::EC2::Instance"
    )
    assert response.status_code == 200
    node_ids = {n["id"] for n in response.json()["nodes"]}
    assert "__svc__EC2" not in node_ids


# ---------------------------------------------------------------------------
# BA-14: Partial-match containment edges ("Contains Subnet", "Is contained in Vpc")
# ---------------------------------------------------------------------------


def test_ba14_contains_subnet_edge_sets_parentid(client_hierarchy):
    """'Contains Subnet' edge type must resolve subnet-001 parentId = vpc-001."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    # The fixture uses "Contains Subnet" (not bare "Contains")
    assert (
        nodes["subnet-001"]["parentId"] == "vpc-001"
    ), "'Contains Subnet' must be recognised as a containment edge"


def test_ba14_service_group_is_top_level_for_vpc(client_hierarchy):
    """The EC2 service-group node must be the outermost container in snap-002."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert "__svc__EC2" in nodes
    assert nodes["__svc__EC2"]["parentId"] is None


def test_ba14_hierarchy_depth_is_correct(client_hierarchy):
    """Full containment chain: __svc__EC2 → vpc-001 → subnet-001 → i-001."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["vpc-001"]["parentId"] == "__svc__EC2"
    assert nodes["subnet-001"]["parentId"] == "vpc-001"
    assert nodes["i-001"]["parentId"] == "subnet-001"


# ---------------------------------------------------------------------------
# BA-15: VPC-resident resources – EIP (association-only) inferred into VPC;
#        Subnet / RouteTable / NatGateway / Instance placed in VPC box.
#
# snap-003 fixture:
#   vpc-200 ← subnet-200 (Is contained in Vpc)
#   vpc-200 ← rtb-200    (Is contained in Vpc)
#   subnet-200 ← nat-200 (Is contained in Subnet)
#   subnet-200 ← i-200   (Is contained in Subnet)
#   eip-200 → nat-200    (Is associated with — NO containment edge)
# ---------------------------------------------------------------------------


def test_ba15_subnet_parent_is_vpc(client_vpc_full):
    """Subnet with 'Is contained in Vpc' edge must be a direct child of the VPC."""
    response = client_vpc_full.get("/api/snapshots/snap-003/graph")
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["subnet-200"]["parentId"] == "vpc-200"


def test_ba15_route_table_parent_is_vpc(client_vpc_full):
    """RouteTable with 'Is contained in Vpc' edge must be a direct child of the VPC."""
    response = client_vpc_full.get("/api/snapshots/snap-003/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["rtb-200"]["parentId"] == "vpc-200"


def test_ba15_natgateway_parent_is_subnet(client_vpc_full):
    """NatGateway with 'Is contained in Subnet' edge must be a child of the Subnet
    (which is itself inside the VPC, so NatGateway is visually inside the VPC)."""
    response = client_vpc_full.get("/api/snapshots/snap-003/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["nat-200"]["parentId"] == "subnet-200"


def test_ba15_instance_parent_is_subnet(client_vpc_full):
    """EC2 Instance with 'Is contained in Subnet' edge must be a child of the Subnet."""
    response = client_vpc_full.get("/api/snapshots/snap-003/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["i-200"]["parentId"] == "subnet-200"


def test_ba15_eip_inferred_into_vpc(client_vpc_full):
    """EIP with only an association edge to NatGateway must be inferred into the VPC.

    Chain: eip-200 --'Is associated with'--> nat-200 --'Is contained in'--> subnet-200
           subnet-200 --'Is contained in Vpc'--> vpc-200
    Expected: eip-200.parentId == 'vpc-200'
    """
    response = client_vpc_full.get("/api/snapshots/snap-003/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert (
        nodes["eip-200"]["parentId"] == "vpc-200"
    ), "EIP must be inferred into VPC via association→NatGateway→Subnet→VPC chain"


def test_ba15_eip_is_leaf_node(client_vpc_full):
    """EIP is not a container; it must use type='awsNode'."""
    response = client_vpc_full.get("/api/snapshots/snap-003/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["eip-200"]["type"] == "awsNode"
    assert nodes["eip-200"]["data"]["is_container"] is False


def test_ba15_vpc_node_is_container(client_vpc_full):
    """VPC must be flagged as a container (it has children)."""
    response = client_vpc_full.get("/api/snapshots/snap-003/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["vpc-200"]["data"]["is_container"] is True
    assert nodes["vpc-200"]["type"] == "awsGroupNode"


def test_ba15_association_edge_still_present(client_vpc_full):
    """'Is associated with' edge (eip-200 → nat-200) must remain in the edge list."""
    response = client_vpc_full.get("/api/snapshots/snap-003/graph")
    data = response.json()
    edge_pairs = {(e["source"], e["target"]) for e in data["edges"]}
    assert (
        "eip-200",
        "nat-200",
    ) in edge_pairs, (
        "association edge eip-200→nat-200 must be preserved in the edge list"
    )


# ---------------------------------------------------------------------------
# BA-16: Extended VPC-resident types — NetworkAcl, NetworkInterface, ALB
#
# snap-004 fixture:
#   subnet-400 → vpc-400  (Is contained in Vpc)
#   acl-400    → vpc-400  (Is contained in Vpc)
#   eni-400    → subnet-400 (Is contained in Subnet)
#   lambda-400 → subnet-400 (Is associated with — no containment)
#   rds-400    → subnet-400 (Is associated with — no containment)
#   alb-400    → vpc-400  (Is associated with — no containment)
# ---------------------------------------------------------------------------


def test_ba16_network_acl_parent_is_vpc(client_vpc_extended):
    """NetworkAcl with 'Is contained in Vpc' edge must be a direct child of the VPC."""
    response = client_vpc_extended.get("/api/snapshots/snap-004/graph")
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["acl-400"]["parentId"] == "vpc-400"


def test_ba16_network_interface_parent_is_subnet(client_vpc_extended):
    """NetworkInterface with 'Is contained in Subnet' edge must be a child of the Subnet."""
    response = client_vpc_extended.get("/api/snapshots/snap-004/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["eni-400"]["parentId"] == "subnet-400"


def test_ba16_alb_inferred_into_vpc(client_vpc_extended):
    """ALB with only 'Is associated with' VPC edge must be inferred into the VPC
    because AWS::ElasticLoadBalancingV2::LoadBalancer is in _VPC_RESIDENT_TYPES."""
    response = client_vpc_extended.get("/api/snapshots/snap-004/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["alb-400"]["parentId"] == "vpc-400"


# ---------------------------------------------------------------------------
# BA-17: Subnet-level inference — Lambda and RDS placed inside Subnet
#
# Same snap-004 fixture — lambda-400 and rds-400 have only association edges
# pointing to subnet-400.  After _infer_subnet_for_residents, they must land
# directly inside the Subnet (not just anywhere inside the VPC).
# ---------------------------------------------------------------------------


def test_ba17_lambda_inferred_into_subnet(client_vpc_extended):
    """Lambda with 'Is associated with' Subnet edge must be placed inside the Subnet."""
    response = client_vpc_extended.get("/api/snapshots/snap-004/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert (
        nodes["lambda-400"]["parentId"] == "subnet-400"
    ), "Lambda must be inferred into its associated Subnet, not just the VPC"


def test_ba17_rds_instance_inferred_into_subnet(client_vpc_extended):
    """RDS DBInstance with 'Is associated with' Subnet edge must be placed inside the Subnet."""
    response = client_vpc_extended.get("/api/snapshots/snap-004/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert (
        nodes["rds-400"]["parentId"] == "subnet-400"
    ), "RDS DBInstance must be inferred into its associated Subnet, not just the VPC"


# ---------------------------------------------------------------------------
# BA-18: Auto Scaling Group containment
#
# snap-005 fixture:
#   i-500 → asg-500  (Is member of AutoScalingGroup)
# ---------------------------------------------------------------------------


def test_ba18_instance_parent_is_asg(client_asg):
    """EC2 Instance with 'Is member of AutoScalingGroup' edge must be inside the ASG."""
    response = client_asg.get("/api/snapshots/snap-005/graph")
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert (
        nodes["i-500"]["parentId"] == "asg-500"
    ), "'Is member of AutoScalingGroup' must be treated as a containment edge"


def test_ba18_asg_node_is_container(client_asg):
    """ASG must be flagged as a container (is_container=True, type=awsGroupNode)."""
    response = client_asg.get("/api/snapshots/snap-005/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["asg-500"]["data"]["is_container"] is True
    assert nodes["asg-500"]["type"] == "awsGroupNode"


def test_ba18_asg_inside_autoscaling_service_group(client_asg):
    """ASG must be nested inside the __svc__AutoScaling service-group node."""
    response = client_asg.get("/api/snapshots/snap-005/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["asg-500"]["parentId"] == "__svc__AutoScaling"
    assert "__svc__AutoScaling" in nodes


# ---------------------------------------------------------------------------
# BA-19: CloudFormation Stack grouping
#
# snap-006 fixture:
#   stack-600 → i-600      (Contains)
#   stack-600 → nstack-600 (Contains)
# No prod code change needed — _build_parent_map handles 'Contains' generically.
# ---------------------------------------------------------------------------


def test_ba19_instance_parent_is_cfn_stack(client_cfn):
    """EC2 Instance managed by a Stack must have parentId == stack_id."""
    response = client_cfn.get("/api/snapshots/snap-006/graph")
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["i-600"]["parentId"] == "stack-600"


def test_ba19_nested_stack_parent_is_parent_stack(client_cfn):
    """Nested Stack must have parentId == parent stack_id."""
    response = client_cfn.get("/api/snapshots/snap-006/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["nstack-600"]["parentId"] == "stack-600"


def test_ba19_stack_node_is_container(client_cfn):
    """CloudFormation Stack must be flagged as a container (is_container=True, type=awsGroupNode)."""
    response = client_cfn.get("/api/snapshots/snap-006/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["stack-600"]["data"]["is_container"] is True
    assert nodes["stack-600"]["type"] == "awsGroupNode"


def test_ba19_stack_inside_cloudformation_service_group(client_cfn):
    """Root stack must be nested inside the __svc__CloudFormation service-group node."""
    response = client_cfn.get("/api/snapshots/snap-006/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["stack-600"]["parentId"] == "__svc__CloudFormation"
    assert "__svc__CloudFormation" in nodes


# ---------------------------------------------------------------------------
# BA-20: RDS Cluster → DB Instance
#
# snap-007 fixture:
#   cluster-700 → db-700  (Contains DBInstance)
# No prod code change needed — 'Contains DBInstance' starts with 'contains'.
# ---------------------------------------------------------------------------


def test_ba20_db_instance_parent_is_cluster(client_rds_cluster):
    """RDS DBInstance with 'Contains DBInstance' edge must have parentId == cluster_id."""
    response = client_rds_cluster.get("/api/snapshots/snap-007/graph")
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["db-700"]["parentId"] == "cluster-700"


def test_ba20_rds_cluster_node_is_container(client_rds_cluster):
    """RDS Cluster must be flagged as a container (is_container=True, type=awsGroupNode)."""
    response = client_rds_cluster.get("/api/snapshots/snap-007/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["cluster-700"]["data"]["is_container"] is True
    assert nodes["cluster-700"]["type"] == "awsGroupNode"


# ---------------------------------------------------------------------------
# BA-21: ECS Cluster → ECS Service
#
# snap-008 fixture:
#   ecs-800 → svc-800  (Contains)
# No prod code change needed — handled by _build_parent_map.
# ---------------------------------------------------------------------------


def test_ba21_ecs_service_parent_is_cluster(client_ecs):
    """ECS Service with 'Contains' edge from Cluster must have parentId == cluster_id."""
    response = client_ecs.get("/api/snapshots/snap-008/graph")
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["svc-800"]["parentId"] == "ecs-800"


def test_ba21_ecs_cluster_node_is_container(client_ecs):
    """ECS Cluster must be flagged as a container (is_container=True, type=awsGroupNode)."""
    response = client_ecs.get("/api/snapshots/snap-008/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["ecs-800"]["data"]["is_container"] is True
    assert nodes["ecs-800"]["type"] == "awsGroupNode"


# ---------------------------------------------------------------------------
# BA-22: Node depth field — every node exposes a numeric 'depth' in its data
# ---------------------------------------------------------------------------


def test_ba22_service_group_depth_is_zero(client_seeded):
    """Service-group virtual nodes (root level) must have depth == 0."""
    response = client_seeded.get("/api/snapshots/snap-001/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["__svc__EC2"]["data"]["depth"] == 0


def test_ba22_vpc_depth_is_one(client_hierarchy):
    """VPC nested inside its service-group must have depth == 1."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["vpc-001"]["data"]["depth"] == 1


def test_ba22_subnet_depth_is_two(client_hierarchy):
    """Subnet nested inside VPC must have depth == 2."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["subnet-001"]["data"]["depth"] == 2


def test_ba22_instance_depth_is_three(client_hierarchy):
    """EC2 Instance nested inside Subnet must have depth == 3."""
    response = client_hierarchy.get("/api/snapshots/snap-002/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["i-001"]["data"]["depth"] == 3


# ---------------------------------------------------------------------------
# BA-23: S3 Bucket hierarchy — S3::AccessPoint placed inside its parent Bucket
#
# snap-009 fixture:
#   s3-bucket-001  AWS::S3::Bucket
#   s3-ap-001      AWS::S3::AccessPoint  ("Is associated with bucket" → s3-bucket-001)
#
# Design intent
# -------------
# S3 AccessPoints have no containment edge in AWS Config snapshots; only an
# association edge to the parent Bucket.  The _infer_s3_hierarchy() function
# must treat AWS::S3::Bucket as a container and place sub-resources inside it
# via association edges.
# ---------------------------------------------------------------------------


def test_ba23_s3_access_point_parent_is_bucket(client_s3):
    """S3 AccessPoint with association edge to Bucket must have parentId == bucket_id."""
    response = client_s3.get("/api/snapshots/snap-009/graph")
    assert response.status_code == 200
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["s3-ap-001"]["parentId"] == "s3-bucket-001"


def test_ba23_s3_bucket_is_container(client_s3):
    """S3 Bucket with a child AccessPoint must be flagged as container (awsGroupNode)."""
    response = client_s3.get("/api/snapshots/snap-009/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["s3-bucket-001"]["data"]["is_container"] is True
    assert nodes["s3-bucket-001"]["type"] == "awsGroupNode"


def test_ba23_s3_bucket_inside_s3_service_group(client_s3):
    """Root S3 Bucket must be nested inside the __svc__S3 service-group node."""
    response = client_s3.get("/api/snapshots/snap-009/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["s3-bucket-001"]["parentId"] == "__svc__S3"
    assert "__svc__S3" in nodes


def test_ba23_s3_bucket_depth_is_one(client_s3):
    """S3 Bucket (inside service group) must have depth == 1."""
    response = client_s3.get("/api/snapshots/snap-009/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["s3-bucket-001"]["data"]["depth"] == 1


def test_ba23_s3_access_point_depth_is_two(client_s3):
    """S3 AccessPoint (inside Bucket inside service group) must have depth == 2."""
    response = client_s3.get("/api/snapshots/snap-009/graph")
    nodes = {n["id"]: n for n in response.json()["nodes"]}
    assert nodes["s3-ap-001"]["data"]["depth"] == 2
