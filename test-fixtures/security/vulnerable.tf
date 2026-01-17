# Vulnerable Terraform Configuration - Test Fixture
# This file intentionally contains security misconfigurations for testing

# IAC-020: Hardcoded AWS credentials
provider "aws" {
  region     = "us-west-2"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# IAC-015: S3 bucket with public access
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-bucket"
  acl    = "public-read-write"

  tags = {
    Environment = "test"
  }
}

# IAC-015: Public access block disabled
resource "aws_s3_bucket_public_access_block" "vulnerable_block" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# IAC-016: S3 bucket without encryption
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-bucket"
  acl    = "private"
  # No server_side_encryption_configuration
}

# IAC-017: Security group with wide open access
resource "aws_security_group" "vulnerable_sg" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port        = 0
    to_port          = 65535
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAC-018: RDS publicly accessible
# IAC-019: RDS without encryption
# IAC-020: Hardcoded password
resource "aws_db_instance" "vulnerable_db" {
  identifier        = "vulnerable-database"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  db_name  = "mydb"
  username = "admin"
  password = "SuperSecretPassword123!"

  publicly_accessible = true
  storage_encrypted   = false

  skip_final_snapshot = true
}

# IAC-021: EBS volume without encryption
resource "aws_ebs_volume" "vulnerable_volume" {
  availability_zone = "us-west-2a"
  size              = 100
  encrypted         = false

  tags = {
    Name = "VulnerableVolume"
  }
}

# IAC-021: EC2 instance with unencrypted EBS
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"

  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 50
    # encrypted not set
  }

  tags = {
    Name = "VulnerableInstance"
  }
}

# IAC-022: CloudTrail with missing security features
resource "aws_cloudtrail" "vulnerable_trail" {
  name           = "vulnerable-trail"
  s3_bucket_name = aws_s3_bucket.vulnerable_bucket.id

  enable_logging                = false
  include_global_service_events = false
  is_multi_region_trail         = false
  enable_log_file_validation    = false
}
