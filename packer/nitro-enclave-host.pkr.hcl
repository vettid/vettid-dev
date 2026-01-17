# VettID Nitro Enclave Host AMI
#
# This Packer configuration builds an AMI for running VettID Nitro Enclaves.
# The AMI includes:
# - Nitro CLI tools for enclave management
# - Pre-built Enclave Image File (EIF)
# - Parent process for host-to-enclave communication
# - Systemd services for automatic startup
#
# Build with: packer build -var 'aws_region=us-east-1' nitro-enclave-host.pkr.hcl

packer {
  required_plugins {
    amazon = {
      version = ">= 1.2.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

# Variables
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type        = string
  default     = "c6a.2xlarge"
  description = "Must be Nitro-enabled instance type for building EIF"
}

variable "ami_name_prefix" {
  type    = string
  default = "vettid-nitro-enclave"
}

variable "enclave_memory_mib" {
  type        = number
  default     = 12288
  description = "Memory allocated to the Nitro Enclave (12 GB optimized for native Go handlers)"
}

variable "enclave_cpu_count" {
  type        = number
  default     = 6
  description = "vCPUs allocated to the Nitro Enclave (6 of 8 on c6a.2xlarge, leaving 2 for parent)"
}

variable "allocator_memory_mib" {
  type        = number
  default     = 12288
  description = "Memory to reserve for Nitro Enclaves (must be >= enclave_memory_mib)"
}

# Data source to find the latest Amazon Linux 2023 AMI
data "amazon-ami" "al2023" {
  filters = {
    name                = "al2023-ami-*-kernel-*-x86_64"
    root-device-type    = "ebs"
    virtualization-type = "hvm"
    architecture        = "x86_64"
  }
  most_recent = true
  owners      = ["amazon"]
  region      = var.aws_region
}

# Source configuration
source "amazon-ebs" "nitro-enclave" {
  ami_name        = "${var.ami_name_prefix}-{{timestamp}}"
  ami_description = "VettID Nitro Enclave Host - Multi-tenant vault architecture"
  instance_type   = var.instance_type
  region          = var.aws_region
  source_ami      = data.amazon-ami.al2023.id

  # IAM instance profile for SSM parameter writes during build
  iam_instance_profile = "vettid-packer-build-profile"

  # Enable Nitro Enclave support during build
  ena_support   = true

  # Use nitro-enabled instance for building
  launch_block_device_mappings {
    device_name           = "/dev/xvda"
    volume_size           = 30
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  ssh_username = "ec2-user"

  # Tags for the AMI
  tags = {
    Name        = "${var.ami_name_prefix}"
    Component   = "nitro-enclave"
    Project     = "VettID"
    BuildTime   = "{{timestamp}}"
    BaseAMI     = "{{ .SourceAMI }}"
    EnclaveMem  = "${var.enclave_memory_mib}"
    EnclaveCPU  = "${var.enclave_cpu_count}"
  }

  # Tags for snapshots
  snapshot_tags = {
    Name      = "${var.ami_name_prefix}-snapshot"
    Component = "nitro-enclave"
    Project   = "VettID"
  }
}

# Build definition
build {
  name    = "vettid-nitro-enclave"
  sources = ["source.amazon-ebs.nitro-enclave"]

  # Install system dependencies
  provisioner "shell" {
    inline = [
      "echo '=== Installing system dependencies ==='",
      "sudo dnf update -y",
      "sudo dnf install -y docker git golang jq aws-cli",

      "echo '=== Installing Nitro CLI ==='",
      "sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel",

      "echo '=== Configuring Docker and Nitro ==='",
      "sudo systemctl enable docker",
      "sudo systemctl start docker",
      "sudo usermod -aG docker ec2-user",
      "sudo usermod -aG ne ec2-user",

      "echo '=== Configuring Nitro Enclave allocator ==='",
      "sudo mkdir -p /etc/nitro_enclaves",
      "echo '---' | sudo tee /etc/nitro_enclaves/allocator.yaml",
      "echo 'memory_mib: ${var.allocator_memory_mib}' | sudo tee -a /etc/nitro_enclaves/allocator.yaml",
      "echo 'cpu_count: ${var.enclave_cpu_count}' | sudo tee -a /etc/nitro_enclaves/allocator.yaml",

      "echo '=== Enabling Nitro Enclave allocator service ==='",
      "sudo systemctl enable nitro-enclaves-allocator",
      "sudo systemctl start nitro-enclaves-allocator || true",
    ]
  }

  # Create destination directory for file upload
  provisioner "shell" {
    inline = [
      "mkdir -p /tmp/enclave",
    ]
  }

  # Copy enclave source code
  provisioner "file" {
    source      = "../enclave/"
    destination = "/tmp/enclave/"
  }

  # Build enclave and parent process
  provisioner "shell" {
    inline = [
      "echo '=== Building parent process ==='",
      "cd /tmp/enclave/parent",
      "go build -ldflags='-s -w' -o /tmp/parent .",
      "sudo mv /tmp/parent /usr/local/bin/vettid-parent",
      "sudo chmod +x /usr/local/bin/vettid-parent",

      "echo '=== Building enclave Docker image ==='",
      "cd /tmp/enclave",
      "sudo docker build -f Dockerfile.enclave -t vettid-enclave:latest .",

      "echo '=== Building Enclave Image File (EIF) ==='",
      "sudo nitro-cli build-enclave --docker-uri vettid-enclave:latest --output-file /tmp/vettid-vault-enclave.eif",

      "echo '=== Installing EIF ==='",
      "sudo mkdir -p /opt/vettid/enclave",
      "sudo mv /tmp/vettid-vault-enclave.eif /opt/vettid/enclave/",
      "sudo chmod 644 /opt/vettid/enclave/vettid-vault-enclave.eif",

      "echo '=== Extracting PCR values ==='",
      "sudo nitro-cli describe-eif --eif-path /opt/vettid/enclave/vettid-vault-enclave.eif | sudo tee /opt/vettid/enclave/pcr-values.json",

      "echo '=== Uploading PCR values to SSM Parameter Store ==='",
      "PCR_JSON=$(cat /opt/vettid/enclave/pcr-values.json)",
      "PCR0=$(echo $PCR_JSON | jq -r '.Measurements.PCR0')",
      "PCR1=$(echo $PCR_JSON | jq -r '.Measurements.PCR1')",
      "PCR2=$(echo $PCR_JSON | jq -r '.Measurements.PCR2')",
      "VERSION=$(date -u +%Y-%m-%d-v1)",
      "PUBLISHED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)",

      "# Create SSM parameters with versioning",
      "# Combined JSON parameter (for reference)",
      "aws ssm put-parameter --name '/vettid/enclave/pcr/current' --type 'String' --overwrite --value \"$(echo $PCR_JSON | jq -c '{PCR0: .Measurements.PCR0, PCR1: .Measurements.PCR1, PCR2: .Measurements.PCR2, version: \"'$VERSION'\", published_at: \"'$PUBLISHED_AT'\"}')\" --region ${var.aws_region}",

      "# Individual PCR parameters (used by CDK for KMS key policy)",
      "aws ssm put-parameter --name '/vettid/enclave/pcr/pcr0' --type 'String' --overwrite --value \"$PCR0\" --region ${var.aws_region}",
      "aws ssm put-parameter --name '/vettid/enclave/pcr/pcr1' --type 'String' --overwrite --value \"$PCR1\" --region ${var.aws_region}",
      "aws ssm put-parameter --name '/vettid/enclave/pcr/pcr2' --type 'String' --overwrite --value \"$PCR2\" --region ${var.aws_region}",

      "echo '=== PCR values uploaded to SSM ==='",
      "echo \"PCR0: $PCR0\"",
      "echo \"PCR1: $PCR1\"",
      "echo \"PCR2: $PCR2\"",

      "echo '=== Cleaning up ==='",
      "sudo docker rmi vettid-enclave:latest || true",
      "rm -rf /tmp/enclave",
    ]
  }

  # Create configuration directory and default config
  provisioner "shell" {
    inline = [
      "echo '=== Creating configuration ==='",
      "sudo mkdir -p /etc/vettid",

      "sudo tee /etc/vettid/parent.yaml << 'EOF'",
      "# VettID Nitro Enclave Parent Configuration",
      "# This file is managed by SSM Parameter Store in production",
      "",
      "enclave:",
      "  eif_path: /opt/vettid/enclave/vettid-vault-enclave.eif",
      "  memory_mib: ${var.enclave_memory_mib}",
      "  cpu_count: ${var.enclave_cpu_count}",
      "  cid: 16",
      "  debug_mode: false",
      "",
      "vsock:",
      "  port: 5000",
      "",
      "nats:",
      "  # Internal NATS endpoint (via VPC peering)",
      "  url: nats://nats.internal.vettid.dev:4222",
      "",
      "s3:",
      "  # Vault data bucket (set via environment or SSM)",
      "  bucket: \"\"",
      "  region: us-east-1",
      "",
      "health:",
      "  port: 8080",
      "  check_interval: 30s",
      "",
      "logging:",
      "  level: info",
      "  format: json",
      "EOF",

      "sudo chmod 644 /etc/vettid/parent.yaml",
    ]
  }

  # Create systemd services
  provisioner "shell" {
    inline = [
      "echo '=== Creating systemd services ==='",

      "# Enclave service - runs the Nitro Enclave",
      "sudo tee /etc/systemd/system/vettid-enclave.service << 'EOF'",
      "[Unit]",
      "Description=VettID Nitro Enclave",
      "After=nitro-enclaves-allocator.service docker.service",
      "Requires=nitro-enclaves-allocator.service",
      "",
      "[Service]",
      "Type=oneshot",
      "RemainAfterExit=yes",
      "ExecStart=/usr/bin/nitro-cli run-enclave --enclave-cid 16 --eif-path /opt/vettid/enclave/vettid-vault-enclave.eif --memory ${var.enclave_memory_mib} --cpu-count ${var.enclave_cpu_count}",
      "ExecStop=/usr/bin/nitro-cli terminate-enclave --all",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",

      "# Parent service - host-side process for NATS/S3 communication",
      "sudo tee /etc/systemd/system/vettid-parent.service << 'EOF'",
      "[Unit]",
      "Description=VettID Enclave Parent Process",
      "After=vettid-enclave.service network-online.target",
      "Requires=vettid-enclave.service",
      "Wants=network-online.target",
      "",
      "[Service]",
      "Type=simple",
      "User=root",
      "ExecStart=/usr/local/bin/vettid-parent --config /etc/vettid/parent.yaml",
      "Restart=always",
      "RestartSec=5",
      "Environment=AWS_REGION=us-east-1",
      "",
      "# Security hardening",
      "NoNewPrivileges=true",
      "ProtectSystem=strict",
      "ProtectHome=true",
      "ReadWritePaths=/var/log/vettid /var/lib/vettid",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",

      "# Create log and data directories",
      "sudo mkdir -p /var/log/vettid /var/lib/vettid",
      "sudo chmod 755 /var/log/vettid /var/lib/vettid",

      "# Enable services",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable vettid-enclave.service",
      "sudo systemctl enable vettid-parent.service",
    ]
  }

  # Create health check script for ALB/NLB
  provisioner "shell" {
    inline = [
      "echo '=== Creating health check endpoint ==='",

      "sudo tee /usr/local/bin/vettid-health-check << 'EOF'",
      "#!/bin/bash",
      "# Simple health check for load balancer",
      "",
      "# Check if enclave is running",
      "ENCLAVE_STATUS=$(nitro-cli describe-enclaves 2>/dev/null | jq -r '.[0].State // \"NONE\"')",
      "if [ \"$ENCLAVE_STATUS\" != \"RUNNING\" ]; then",
      "  echo '{\"status\": \"unhealthy\", \"reason\": \"enclave_not_running\"}'",
      "  exit 1",
      "fi",
      "",
      "# Check if parent process is running",
      "if ! pgrep -x vettid-parent > /dev/null; then",
      "  echo '{\"status\": \"unhealthy\", \"reason\": \"parent_not_running\"}'",
      "  exit 1",
      "fi",
      "",
      "# Check parent health endpoint",
      "PARENT_HEALTH=$(curl -sf http://127.0.0.1:8080/health 2>/dev/null)",
      "if [ $? -ne 0 ]; then",
      "  echo '{\"status\": \"unhealthy\", \"reason\": \"parent_health_check_failed\"}'",
      "  exit 1",
      "fi",
      "",
      "echo '{\"status\": \"healthy\", \"enclave\": \"running\", \"parent\": \"running\"}'",
      "exit 0",
      "EOF",

      "sudo chmod +x /usr/local/bin/vettid-health-check",
    ]
  }

  # Final cleanup
  provisioner "shell" {
    inline = [
      "echo '=== Final cleanup ==='",
      "sudo dnf clean all",
      "sudo rm -rf /var/cache/dnf",
      "sudo rm -rf /tmp/*",
      "rm -rf ~/.cache",

      "echo '=== AMI build complete ==='",
      "echo 'EIF location: /opt/vettid/enclave/vettid-vault-enclave.eif'",
      "echo 'Parent binary: /usr/local/bin/vettid-parent'",
      "echo 'Config: /etc/vettid/parent.yaml'",
      "echo 'Services: vettid-enclave.service, vettid-parent.service'",
    ]
  }

  # Post-processor to output AMI ID
  post-processor "manifest" {
    output     = "manifest.json"
    strip_path = true
  }

  # Update SSM with the new AMI ID after build completes
  post-processor "shell-local" {
    inline = [
      "echo '=== Updating AMI ID in SSM Parameter Store ==='",
      "AMI_ID=$(jq -r '.builds[-1].artifact_id | split(\":\")[1]' manifest.json)",
      "echo \"New AMI ID: $AMI_ID\"",
      "aws ssm put-parameter --name '/vettid/enclave/ami-id' --type 'String' --overwrite --value \"$AMI_ID\" --region ${var.aws_region}",
      "echo '=== SSM parameters updated ==='",
      "echo 'Ready for CDK deploy to pick up new AMI and PCR values'",
    ]
  }
}
