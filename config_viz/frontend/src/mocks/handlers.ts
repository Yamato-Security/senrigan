import { http, HttpResponse } from "msw";
import type { Snapshot, GraphData, ResourceDetail } from "../types";

export const mockSnapshots: Snapshot[] = [
  {
    snapshot_id: "snap-001",
    account_id: "123456789012",
    aws_region: "us-east-1",
    captured_at: "2026-01-01T00:00:00",
    source_path: "/data/snap-001.json",
    record_count: 42,
  },
  {
    snapshot_id: "snap-002",
    account_id: "123456789012",
    aws_region: "ap-northeast-1",
    captured_at: "2026-01-02T00:00:00",
    source_path: "/data/snap-002.json",
    record_count: 10,
  },
];

export const mockGraphData: GraphData = {
  nodes: [
    {
      id: "vpc-123",
      type: "awsGroupNode",
      position: { x: 0, y: 0 },
      parentId: null,
      data: {
        resource_id: "vpc-123",
        resource_type: "AWS::EC2::VPC",
        resource_name: "my-vpc",
        aws_region: "us-east-1",
        is_container: true,
      },
    },
    {
      id: "ec2-456",
      type: "awsNode",
      position: { x: 0, y: 0 },
      parentId: "vpc-123",
      data: {
        resource_id: "ec2-456",
        resource_type: "AWS::EC2::Instance",
        resource_name: "my-instance",
        aws_region: "us-east-1",
        is_container: false,
      },
    },
    {
      id: "s3-789",
      type: "awsNode",
      position: { x: 0, y: 0 },
      parentId: null,
      data: {
        resource_id: "s3-789",
        resource_type: "AWS::S3::Bucket",
        resource_name: "my-bucket",
        aws_region: "us-east-1",
        is_container: false,
      },
    },
  ],
  edges: [
    {
      id: "ec2-456__s3-789__uses",
      source: "ec2-456",
      target: "s3-789",
      label: "uses",
    },
  ],
};

export const mockResourceDetail: ResourceDetail = {
  resource_id: "ec2-456",
  snapshot_id: "snap-001",
  resource_type: "AWS::EC2::Instance",
  aws_region: "us-east-1",
  resource_name: "my-instance",
  configuration: { instanceType: "t3.micro", state: "running" },
  tags: { Name: "my-instance", Env: "prod" },
};

export const handlers = [
  http.get("/api/snapshots", () => {
    return HttpResponse.json(mockSnapshots);
  }),

  http.get("/api/snapshots/:id/resource-types", () => {
    return HttpResponse.json(["AWS::EC2::VPC", "AWS::EC2::Instance", "AWS::S3::Bucket"]);
  }),

  http.get("/api/snapshots/:id/graph", () => {
    return HttpResponse.json(mockGraphData);
  }),

  http.get("/api/snapshots/:snapshotId/resources/:resourceId", () => {
    return HttpResponse.json(mockResourceDetail);
  }),
];

