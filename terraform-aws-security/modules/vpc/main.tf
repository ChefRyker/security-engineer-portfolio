# modules/vpc/main.tf
# 3-tier VPC: public (ALB), private (app), db (data)
# VPC Flow Logs enabled to S3 for all traffic

locals {
  azs_count = length(var.availability_zones)

  # Subnet CIDR slices — /24 per subnet
  public_cidrs  = [for i in range(local.azs_count) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_cidrs = [for i in range(local.azs_count) : cidrsubnet(var.vpc_cidr, 8, i + 10)]
  db_cidrs      = [for i in range(local.azs_count) : cidrsubnet(var.vpc_cidr, 8, i + 20)]
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.environment}-vpc" }
}

# ---------------------------------------------------------------------------
# Subnets
# ---------------------------------------------------------------------------
resource "aws_subnet" "public" {
  count                   = local.azs_count
  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false # explicitly disable; attach EIP when needed

  tags = { Name = "${var.environment}-public-${var.availability_zones[count.index]}", Tier = "public" }
}

resource "aws_subnet" "private" {
  count             = local.azs_count
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = { Name = "${var.environment}-private-${var.availability_zones[count.index]}", Tier = "private" }
}

resource "aws_subnet" "db" {
  count             = local.azs_count
  vpc_id            = aws_vpc.main.id
  cidr_block        = local.db_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = { Name = "${var.environment}-db-${var.availability_zones[count.index]}", Tier = "db" }
}

# ---------------------------------------------------------------------------
# Internet Gateway + NAT Gateway
# ---------------------------------------------------------------------------
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.environment}-igw" }
}

resource "aws_eip" "nat" {
  count  = local.azs_count
  domain = "vpc"
  tags   = { Name = "${var.environment}-nat-eip-${count.index}" }
}

resource "aws_nat_gateway" "main" {
  count         = local.azs_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = { Name = "${var.environment}-nat-${var.availability_zones[count.index]}" }
}

# ---------------------------------------------------------------------------
# Route Tables
# ---------------------------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  tags = { Name = "${var.environment}-public-rt" }
}

resource "aws_route_table_association" "public" {
  count          = local.azs_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  count  = local.azs_count
  vpc_id = aws_vpc.main.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }
  tags = { Name = "${var.environment}-private-rt-${count.index}" }
}

resource "aws_route_table_association" "private" {
  count          = local.azs_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_route_table" "db" {
  vpc_id = aws_vpc.main.id
  # No default route — db tier has no internet access
  tags = { Name = "${var.environment}-db-rt" }
}

resource "aws_route_table_association" "db" {
  count          = local.azs_count
  subnet_id      = aws_subnet.db[count.index].id
  route_table_id = aws_route_table.db.id
}

# ---------------------------------------------------------------------------
# VPC Flow Logs — ALL traffic to S3
# ---------------------------------------------------------------------------
resource "aws_flow_log" "main" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${var.log_bucket_arn}/vpc-flow-logs/"

  tags = { Name = "${var.environment}-flow-logs" }
}

# ---------------------------------------------------------------------------
# Default security group — deny all (CIS 5.4)
# ---------------------------------------------------------------------------
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # No ingress or egress rules — effectively denies all traffic
  tags = { Name = "${var.environment}-default-sg-DO-NOT-USE" }
}
