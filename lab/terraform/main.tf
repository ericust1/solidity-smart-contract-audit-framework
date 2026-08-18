terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}

variable "instance_type" {
  default = "t3.xlarge"
}

variable "allowed_cidr" {
  default = ["0.0.0.0/0"]
}

resource "aws_security_group" "eth_node_sg" {
  name        = "eth-node-sg"
  description = "Security group for Ethereum node RPC access"

  ingress {
    description = "RPC port 8545"
    from_port   = 8545
    to_port     = 8545
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr
  }

  ingress {
    description = "WS port 8546"
    from_port   = 8546
    to_port     = 8546
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "eth_node" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  security_groups = [aws_security_group.eth_node_sg.name]

  root_block_device {
    volume_size = 100
    volume_type = "gp3"
  }

  tags = {
    Name        = "solidity-audit-eth-node"
    Environment = "audit-lab"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

resource "aws_s3_bucket" "audit_reports" {
  bucket = "solidity-audit-reports"

  tags = {
    Name        = "audit-reports"
    Environment = "audit-lab"
  }
}

resource "aws_s3_bucket_versioning" "audit_reports_versioning" {
  bucket = aws_s3_bucket.audit_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_reports_lifecycle" {
  bucket = aws_s3_bucket.audit_reports.id

  rule {
    id     = "archive-old-reports"
    status = "Enabled"
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }
  }
}

output "eth_node_ip" {
  value       = aws_instance.eth_node.public_ip
  description = "Public IP of the Ethereum node instance"
}

output "rpc_endpoint" {
  value       = "http://${aws_instance.eth_node.public_ip}:8545"
  description = "RPC endpoint for the Ethereum node"
}

output "s3_bucket" {
  value       = aws_s3_bucket.audit_reports.bucket
  description = "S3 bucket for audit reports"
}
