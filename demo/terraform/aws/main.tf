provider "aws" {
  region = "us-east-1"
}

# Violation: hardcoded AWS key
variable "access_key" {
  default = "AKIA1234567890123456"
}

# Violation: password variable without sensitive
variable "db_password" {
  description = "Database password"
  type        = string
}

# OK: password with sensitive
variable "api_key" {
  description = "API key"
  type        = string
  sensitive   = true
}

resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  tags = {
    Name = "web-server"
  }
}

resource "aws_security_group" "web" {
  name = "web-sg"

  # Violation: open SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
