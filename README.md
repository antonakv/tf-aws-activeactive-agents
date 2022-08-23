# tf-aws-activeactive-agents
Install TFE with 2 Agents, test workspace plan/apply

This manual is dedicated to Install Terraform Enterprise with 2 agents.

## Requirements

- Hashicorp terraform recent version installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in .aws/credentials file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

- Configured CloudFlare DNS zone for domain `my-domain-here.com`
[Cloudflare DNS zone setup](https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/)

- SSL certificate and SSL key files for the corresponding domain name
[Certbot manual](https://certbot.eff.org/instructions)

- Created Amazon EC2 key pair for Linux instance
[Creating a public hosted zone](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)

## Preparation 

- Clone git repository

```bash
git clone https://github.com/antonakv/tf-aws-activeactive-agents.git
```

```bash
Cloning into 'tf-aws-activeactive-agents'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 12 (delta 1), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (1/1), done.
```

- Change folder to tf-aws-activeactive-agents

```bash
cd tf-aws-activeactive-agents
```

- Create file terraform.tfvars with following contents

```
region                  = "eu-central-1"
tfe_license_path        = "upload/license.rli"
cidr_vpc                = "10.5.0.0/16"
cidr_subnet_private_1   = "10.5.1.0/24"
cidr_subnet_private_2   = "10.5.2.0/24"
cidr_subnet_public_1    = "10.5.3.0/24"
cidr_subnet_public_2    = "10.5.4.0/24"
instance_type_jump      = "t3.medium"
instance_type_redis     = "cache.t3.medium"
key_name                = "aakulov"
jump_ami                = "ami-057b567814acd0cda-your-ami"
aws_ami                 = "ami-057b567814acd0cda-your-ami"
agent_ami               = "ami-0f0bd2f63fe01d0bb-your-ami"
db_instance_type        = "db.t3.medium"
instance_type           = "t3.2xlarge"
instance_type_agent     = "t3.medium"
release_sequence        = 652
tfe_hostname            = "tfeaa.domain.cc"
tfe_hostname_jump       = "tfeaajump.domain.cc"
postgres_db_name        = "mydbtfe"
postgres_engine_version = "12.7"
postgres_username       = "postgres"
ssl_cert_path           = "/letsencrypt-ssl-cert/config/live/domain.cc/cert.pem"
ssl_key_path            = "/letsencrypt-ssl-cert/config/live/domain.cc/privkey.pem"
ssl_chain_path          = "/letsencrypt-ssl-cert/config/live/domain.cc/chain.pem"
ssl_fullchain_cert_path = "/letsencrypt-ssl-cert/config/live/domain.cc/fullchain.pem"
domain_name             = "domain.cc"
cloudflare_zone_id      = "36b3ef5080f2c6f91e5136854e9f29fb"
cloudflare_api_token    = "XXPyfaSeFh2j8RxsAljiJiDEffPASNWhdTF8pDwe"
asg_min_nodes           = 2
asg_max_nodes           = 2
asg_desired_nodes       = 2
lb_ssl_policy           = "ELBSecurityPolicy-2016-08"
agent_token             = "empty"
asg_min_agents          = 0
asg_max_agents          = 0
asg_desired_agents      = 0

```

## Run terraform code

- In the same folder you were before, run 

```bash
terraform init
```

Sample result

```
$ terraform init

Initializing the backend...

Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 3.52"...
- Finding hashicorp/tls versions matching "~> 3.1.0"...
- Finding hashicorp/template versions matching "~> 2.2.0"...
- Installing hashicorp/aws v3.66.0...
- Installed hashicorp/aws v3.66.0 (signed by HashiCorp)
- Installing hashicorp/tls v3.1.0...
- Installed hashicorp/tls v3.1.0 (signed by HashiCorp)
- Installing hashicorp/template v2.2.0...
- Installed hashicorp/template v2.2.0 (signed by HashiCorp)

Terraform has created a lock file .terraform.lock.hcl to record the provider
selections it made above. Include this file in your version control repository
so that Terraform can guarantee to make the same selections by default when
you run "terraform init" in the future.

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.

```

- Run the `terraform apply`

Expected result:

```
% terraform apply --auto-approve
data.local_sensitive_file.sslkey: Reading...
data.local_sensitive_file.sslcert: Reading...
data.local_sensitive_file.sslchain: Reading...
data.local_sensitive_file.sslcert: Read complete after 0s [id=03a1061535e45b575f310a070f77ab6ba7c314f0]
data.local_sensitive_file.sslkey: Read complete after 0s [id=c55e3e91058bd74118c719cdb13ae552d5b3347c]
data.local_sensitive_file.sslchain: Read complete after 0s [id=35bea03aecd55ca4d525c6b0a45908a19c6986f9]
data.aws_iam_policy_document.instance_role: Reading...
data.aws_iam_policy_document.tfe_asg_discovery: Reading...
data.aws_iam_policy_document.instance_role: Read complete after 0s [id=1903849331]
data.aws_iam_policy_document.tfe_asg_discovery: Read complete after 0s [id=139118870]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.aws_iam_policy_document.secretsmanager will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "secretsmanager" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "secretsmanager:GetSecretValue",
            ]
          + effect    = "Allow"
          + resources = [
              + (known after apply),
              + (known after apply),
              + (known after apply),
              + (known after apply),
            ]
          + sid       = "AllowSecretsManagerSecretAccess"
        }
    }

  # data.aws_iam_policy_document.tfe_data will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "tfe_data" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "s3:GetBucketLocation",
              + "s3:ListBucket",
            ]
          + effect    = "Allow"
          + resources = [
              + (known after apply),
            ]
          + sid       = "AllowS3ListBucketData"

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "AWS"
            }
        }
      + statement {
          + actions   = [
              + "s3:DeleteObject",
              + "s3:GetObject",
              + "s3:PutObject",
            ]
          + effect    = "Allow"
          + resources = [
              + (known after apply),
            ]
          + sid       = "AllowS3ManagementData"

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "AWS"
            }
        }
    }

  # data.aws_instances.tfc_agent will be read during apply
  # (config refers to values not yet known)
 <= data "aws_instances" "tfc_agent" {
      + id                   = (known after apply)
      + ids                  = (known after apply)
      + instance_state_names = [
          + "running",
        ]
      + instance_tags        = {
          + "Name" = (known after apply)
        }
      + private_ips          = (known after apply)
      + public_ips           = (known after apply)

      + filter {
          + name   = "instance.group-id"
          + values = [
              + (known after apply),
            ]
        }
    }

  # data.aws_instances.tfe will be read during apply
  # (config refers to values not yet known)
 <= data "aws_instances" "tfe" {
      + id                   = (known after apply)
      + ids                  = (known after apply)
      + instance_state_names = [
          + "running",
        ]
      + instance_tags        = {
          + "Name" = (known after apply)
        }
      + private_ips          = (known after apply)
      + public_ips           = (known after apply)

      + filter {
          + name   = "instance.group-id"
          + values = [
              + (known after apply),
            ]
        }
    }

  # aws_acm_certificate.tfe will be created
  + resource "aws_acm_certificate" "tfe" {
      + arn                       = (known after apply)
      + certificate_body          = (sensitive)
      + certificate_chain         = (sensitive)
      + domain_name               = (known after apply)
      + domain_validation_options = (known after apply)
      + id                        = (known after apply)
      + private_key               = (sensitive value)
      + status                    = (known after apply)
      + subject_alternative_names = (known after apply)
      + tags_all                  = (known after apply)
      + validation_emails         = (known after apply)
      + validation_method         = (known after apply)
    }

  # aws_autoscaling_group.tfc_agent will be created
  + resource "aws_autoscaling_group" "tfc_agent" {
      + arn                       = (known after apply)
      + availability_zones        = (known after apply)
      + default_cooldown          = (known after apply)
      + desired_capacity          = 0
      + force_delete              = false
      + force_delete_warm_pool    = false
      + health_check_grace_period = 900
      + health_check_type         = "EC2"
      + id                        = (known after apply)
      + launch_configuration      = (known after apply)
      + max_size                  = 0
      + metrics_granularity       = "1Minute"
      + min_size                  = 0
      + name                      = (known after apply)
      + name_prefix               = (known after apply)
      + protect_from_scale_in     = false
      + service_linked_role_arn   = (known after apply)
      + vpc_zone_identifier       = (known after apply)
      + wait_for_capacity_timeout = "10m"

      + tag {
          + key                 = "Name"
          + propagate_at_launch = true
          + value               = (known after apply)
        }
    }

  # aws_autoscaling_group.tfe will be created
  + resource "aws_autoscaling_group" "tfe" {
      + arn                       = (known after apply)
      + availability_zones        = (known after apply)
      + default_cooldown          = (known after apply)
      + desired_capacity          = 2
      + force_delete              = false
      + force_delete_warm_pool    = false
      + health_check_grace_period = 5500
      + health_check_type         = "ELB"
      + id                        = (known after apply)
      + launch_configuration      = (known after apply)
      + max_size                  = 2
      + metrics_granularity       = "1Minute"
      + min_size                  = 2
      + name                      = (known after apply)
      + name_prefix               = (known after apply)
      + protect_from_scale_in     = false
      + service_linked_role_arn   = (known after apply)
      + target_group_arns         = (known after apply)
      + vpc_zone_identifier       = (known after apply)
      + wait_for_capacity_timeout = "10m"

      + tag {
          + key                 = "Name"
          + propagate_at_launch = true
          + value               = (known after apply)
        }
    }

  # aws_db_instance.tfe will be created
  + resource "aws_db_instance" "tfe" {
      + address                               = (known after apply)
      + allocated_storage                     = 20
      + allow_major_version_upgrade           = false
      + apply_immediately                     = true
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + backup_retention_period               = (known after apply)
      + backup_window                         = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + character_set_name                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_name                               = "mydbtfe"
      + db_subnet_group_name                  = (known after apply)
      + delete_automated_backups              = true
      + deletion_protection                   = false
      + endpoint                              = (known after apply)
      + engine                                = "postgres"
      + engine_version                        = "12.7"
      + engine_version_actual                 = (known after apply)
      + hosted_zone_id                        = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = (known after apply)
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t3.medium"
      + kms_key_id                            = (known after apply)
      + latest_restorable_time                = (known after apply)
      + license_model                         = (known after apply)
      + maintenance_window                    = (known after apply)
      + max_allocated_storage                 = 100
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + multi_az                              = (known after apply)
      + name                                  = (known after apply)
      + nchar_character_set_name              = (known after apply)
      + option_group_name                     = (known after apply)
      + parameter_group_name                  = (known after apply)
      + password                              = (sensitive value)
      + performance_insights_enabled          = false
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = 5432
      + publicly_accessible                   = false
      + replica_mode                          = (known after apply)
      + replicas                              = (known after apply)
      + resource_id                           = (known after apply)
      + skip_final_snapshot                   = true
      + snapshot_identifier                   = (known after apply)
      + status                                = (known after apply)
      + storage_type                          = "gp2"
      + tags                                  = (known after apply)
      + tags_all                              = (known after apply)
      + timezone                              = (known after apply)
      + username                              = "postgres"
      + vpc_security_group_ids                = (known after apply)
    }

  # aws_db_subnet_group.tfe will be created
  + resource "aws_db_subnet_group" "tfe" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = (known after apply)
      + subnet_ids  = (known after apply)
      + tags        = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_eip.aws_nat will be created
  + resource "aws_eip" "aws_nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags_all             = (known after apply)
      + vpc                  = true
    }

  # aws_eip.ssh_jump will be created
  + resource "aws_eip" "ssh_jump" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags_all             = (known after apply)
      + vpc                  = true
    }

  # aws_elasticache_replication_group.redis will be created
  + resource "aws_elasticache_replication_group" "redis" {
      + apply_immediately              = true
      + arn                            = (known after apply)
      + at_rest_encryption_enabled     = true
      + auth_token                     = (sensitive value)
      + auto_minor_version_upgrade     = "true"
      + automatic_failover_enabled     = false
      + cluster_enabled                = (known after apply)
      + configuration_endpoint_address = (known after apply)
      + data_tiering_enabled           = (known after apply)
      + description                    = "Redis replication group for TFE"
      + engine                         = "redis"
      + engine_version                 = "5.0.6"
      + engine_version_actual          = (known after apply)
      + global_replication_group_id    = (known after apply)
      + id                             = (known after apply)
      + maintenance_window             = (known after apply)
      + member_clusters                = (known after apply)
      + multi_az_enabled               = false
      + node_type                      = "cache.t3.medium"
      + num_cache_clusters             = 1
      + num_node_groups                = (known after apply)
      + number_cache_clusters          = (known after apply)
      + parameter_group_name           = "default.redis5.0"
      + port                           = 6380
      + primary_endpoint_address       = (known after apply)
      + reader_endpoint_address        = (known after apply)
      + replicas_per_node_group        = (known after apply)
      + replication_group_description  = (known after apply)
      + replication_group_id           = (known after apply)
      + security_group_ids             = (known after apply)
      + security_group_names           = (known after apply)
      + snapshot_retention_limit       = 0
      + snapshot_window                = (known after apply)
      + subnet_group_name              = (known after apply)
      + tags_all                       = (known after apply)
      + transit_encryption_enabled     = true

      + cluster_mode {
          + num_node_groups         = (known after apply)
          + replicas_per_node_group = (known after apply)
        }
    }

  # aws_elasticache_subnet_group.tfe will be created
  + resource "aws_elasticache_subnet_group" "tfe" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + id          = (known after apply)
      + name        = (known after apply)
      + subnet_ids  = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_iam_instance_profile.tfe will be created
  + resource "aws_iam_instance_profile" "tfe" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = (known after apply)
      + path        = "/"
      + role        = (known after apply)
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_role.instance_role will be created
  + resource "aws_iam_role" "instance_role" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role_policy.secretsmanager will be created
  + resource "aws_iam_role_policy" "secretsmanager" {
      + id     = (known after apply)
      + name   = (known after apply)
      + policy = (known after apply)
      + role   = (known after apply)
    }

  # aws_iam_role_policy.tfe_asg_discovery will be created
  + resource "aws_iam_role_policy" "tfe_asg_discovery" {
      + id     = (known after apply)
      + name   = (known after apply)
      + policy = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = "autoscaling:Describe*"
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + role   = (known after apply)
    }

  # aws_instance.ssh_jump will be created
  + resource "aws_instance" "ssh_jump" {
      + ami                                  = "ami-057b567814acd0cda"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = true
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_stop                     = (known after apply)
      + disable_api_termination              = (known after apply)
      + ebs_optimized                        = (known after apply)
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t3.medium"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = "aakulov"
      + monitoring                           = (known after apply)
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + placement_partition_number           = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = (known after apply)
      + source_dest_check                    = true
      + subnet_id                            = (known after apply)
      + tags                                 = (known after apply)
      + tags_all                             = (known after apply)
      + tenancy                              = (known after apply)
      + user_data                            = (known after apply)
      + user_data_base64                     = (known after apply)
      + user_data_replace_on_change          = false
      + vpc_security_group_ids               = (known after apply)

      + capacity_reservation_specification {
          + capacity_reservation_preference = (known after apply)

          + capacity_reservation_target {
              + capacity_reservation_id                 = (known after apply)
              + capacity_reservation_resource_group_arn = (known after apply)
            }
        }

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + enclave_options {
          + enabled = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + maintenance_options {
          + auto_recovery = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_put_response_hop_limit = 2
          + http_tokens                 = "required"
          + instance_metadata_tags      = "disabled"
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_card_index    = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + private_dns_name_options {
          + enable_resource_name_dns_a_record    = (known after apply)
          + enable_resource_name_dns_aaaa_record = (known after apply)
          + hostname_type                        = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_internet_gateway.igw will be created
  + resource "aws_internet_gateway" "igw" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = (known after apply)
      + tags_all = (known after apply)
      + vpc_id   = (known after apply)
    }

  # aws_launch_configuration.tfc_agent will be created
  + resource "aws_launch_configuration" "tfc_agent" {
      + arn                         = (known after apply)
      + associate_public_ip_address = (known after apply)
      + ebs_optimized               = (known after apply)
      + enable_monitoring           = true
      + iam_instance_profile        = (known after apply)
      + id                          = (known after apply)
      + image_id                    = "ami-0f0bd2f63fe01d0bb"
      + instance_type               = "t3.medium"
      + key_name                    = "aakulov"
      + name                        = (known after apply)
      + name_prefix                 = (known after apply)
      + security_groups             = (known after apply)
      + user_data_base64            = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + no_device             = (known after apply)
          + snapshot_id           = (known after apply)
          + throughput            = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_put_response_hop_limit = 2
          + http_tokens                 = "optional"
        }

      + root_block_device {
          + delete_on_termination = true
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + throughput            = (known after apply)
          + volume_size           = 60
          + volume_type           = "gp2"
        }
    }

  # aws_launch_configuration.tfe will be created
  + resource "aws_launch_configuration" "tfe" {
      + arn                         = (known after apply)
      + associate_public_ip_address = (known after apply)
      + ebs_optimized               = (known after apply)
      + enable_monitoring           = true
      + iam_instance_profile        = (known after apply)
      + id                          = (known after apply)
      + image_id                    = "ami-057b567814acd0cda"
      + instance_type               = "t3.2xlarge"
      + key_name                    = "aakulov"
      + name                        = (known after apply)
      + name_prefix                 = (known after apply)
      + security_groups             = (known after apply)
      + user_data_base64            = (known after apply)

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + no_device             = (known after apply)
          + snapshot_id           = (known after apply)
          + throughput            = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_put_response_hop_limit = 2
          + http_tokens                 = "optional"
        }

      + root_block_device {
          + delete_on_termination = true
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + throughput            = (known after apply)
          + volume_size           = 60
          + volume_type           = "gp2"
        }
    }

  # aws_lb.tfe_lb will be created
  + resource "aws_lb" "tfe_lb" {
      + arn                        = (known after apply)
      + arn_suffix                 = (known after apply)
      + desync_mitigation_mode     = "defensive"
      + dns_name                   = (known after apply)
      + drop_invalid_header_fields = false
      + enable_deletion_protection = false
      + enable_http2               = true
      + enable_waf_fail_open       = false
      + id                         = (known after apply)
      + idle_timeout               = 60
      + internal                   = (known after apply)
      + ip_address_type            = (known after apply)
      + load_balancer_type         = "application"
      + name                       = (known after apply)
      + security_groups            = (known after apply)
      + subnets                    = (known after apply)
      + tags_all                   = (known after apply)
      + vpc_id                     = (known after apply)
      + zone_id                    = (known after apply)

      + subnet_mapping {
          + allocation_id        = (known after apply)
          + ipv6_address         = (known after apply)
          + outpost_id           = (known after apply)
          + private_ipv4_address = (known after apply)
          + subnet_id            = (known after apply)
        }
    }

  # aws_lb_listener.lb_443 will be created
  + resource "aws_lb_listener" "lb_443" {
      + arn               = (known after apply)
      + certificate_arn   = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 443
      + protocol          = "HTTPS"
      + ssl_policy        = "ELBSecurityPolicy-2016-08"
      + tags_all          = (known after apply)

      + default_action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }
    }

  # aws_lb_target_group.tfe_443 will be created
  + resource "aws_lb_target_group" "tfe_443" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + connection_termination             = false
      + deregistration_delay               = "300"
      + id                                 = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancing_algorithm_type      = (known after apply)
      + name                               = (known after apply)
      + port                               = 443
      + preserve_client_ip                 = (known after apply)
      + protocol                           = "HTTPS"
      + protocol_version                   = (known after apply)
      + proxy_protocol_v2                  = false
      + slow_start                         = 0
      + tags_all                           = (known after apply)
      + target_type                        = "instance"
      + vpc_id                             = (known after apply)

      + health_check {
          + enabled             = true
          + healthy_threshold   = 6
          + interval            = 5
          + matcher             = "200-399"
          + path                = "/_health_check"
          + port                = "traffic-port"
          + protocol            = "HTTPS"
          + timeout             = 2
          + unhealthy_threshold = 2
        }

      + stickiness {
          + cookie_duration = 86400
          + enabled         = true
          + type            = "lb_cookie"
        }
    }

  # aws_nat_gateway.nat will be created
  + resource "aws_nat_gateway" "nat" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = (known after apply)
      + tags_all             = (known after apply)
    }

  # aws_route_table.private will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + core_network_arn           = ""
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = ""
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = (known after apply)
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = (known after apply)
      + tags_all         = (known after apply)
      + vpc_id           = (known after apply)
    }

  # aws_route_table.public will be created
  + resource "aws_route_table" "public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + core_network_arn           = ""
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = (known after apply)
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = ""
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = (known after apply)
      + tags_all         = (known after apply)
      + vpc_id           = (known after apply)
    }

  # aws_route_table_association.private1 will be created
  + resource "aws_route_table_association" "private1" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.private2 will be created
  + resource "aws_route_table_association" "private2" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.public1 will be created
  + resource "aws_route_table_association" "public1" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.public2 will be created
  + resource "aws_route_table_association" "public2" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_s3_bucket.tfe_data will be created
  + resource "aws_s3_bucket" "tfe_data" {
      + acceleration_status         = (known after apply)
      + acl                         = (known after apply)
      + arn                         = (known after apply)
      + bucket                      = (known after apply)
      + bucket_domain_name          = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = true
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + object_lock_enabled         = (known after apply)
      + policy                      = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags_all                    = (known after apply)
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)

      + cors_rule {
          + allowed_headers = (known after apply)
          + allowed_methods = (known after apply)
          + allowed_origins = (known after apply)
          + expose_headers  = (known after apply)
          + max_age_seconds = (known after apply)
        }

      + grant {
          + id          = (known after apply)
          + permissions = (known after apply)
          + type        = (known after apply)
          + uri         = (known after apply)
        }

      + lifecycle_rule {
          + abort_incomplete_multipart_upload_days = (known after apply)
          + enabled                                = (known after apply)
          + id                                     = (known after apply)
          + prefix                                 = (known after apply)
          + tags                                   = (known after apply)

          + expiration {
              + date                         = (known after apply)
              + days                         = (known after apply)
              + expired_object_delete_marker = (known after apply)
            }

          + noncurrent_version_expiration {
              + days = (known after apply)
            }

          + noncurrent_version_transition {
              + days          = (known after apply)
              + storage_class = (known after apply)
            }

          + transition {
              + date          = (known after apply)
              + days          = (known after apply)
              + storage_class = (known after apply)
            }
        }

      + logging {
          + target_bucket = (known after apply)
          + target_prefix = (known after apply)
        }

      + object_lock_configuration {
          + object_lock_enabled = (known after apply)

          + rule {
              + default_retention {
                  + days  = (known after apply)
                  + mode  = (known after apply)
                  + years = (known after apply)
                }
            }
        }

      + replication_configuration {
          + role = (known after apply)

          + rules {
              + delete_marker_replication_status = (known after apply)
              + id                               = (known after apply)
              + prefix                           = (known after apply)
              + priority                         = (known after apply)
              + status                           = (known after apply)

              + destination {
                  + account_id         = (known after apply)
                  + bucket             = (known after apply)
                  + replica_kms_key_id = (known after apply)
                  + storage_class      = (known after apply)

                  + access_control_translation {
                      + owner = (known after apply)
                    }

                  + metrics {
                      + minutes = (known after apply)
                      + status  = (known after apply)
                    }

                  + replication_time {
                      + minutes = (known after apply)
                      + status  = (known after apply)
                    }
                }

              + filter {
                  + prefix = (known after apply)
                  + tags   = (known after apply)
                }

              + source_selection_criteria {
                  + sse_kms_encrypted_objects {
                      + enabled = (known after apply)
                    }
                }
            }
        }

      + server_side_encryption_configuration {
          + rule {
              + bucket_key_enabled = (known after apply)

              + apply_server_side_encryption_by_default {
                  + kms_master_key_id = (known after apply)
                  + sse_algorithm     = (known after apply)
                }
            }
        }

      + versioning {
          + enabled    = (known after apply)
          + mfa_delete = (known after apply)
        }

      + website {
          + error_document           = (known after apply)
          + index_document           = (known after apply)
          + redirect_all_requests_to = (known after apply)
          + routing_rules            = (known after apply)
        }
    }

  # aws_s3_bucket_acl.tfe_data will be created
  + resource "aws_s3_bucket_acl" "tfe_data" {
      + acl    = "private"
      + bucket = (known after apply)
      + id     = (known after apply)

      + access_control_policy {
          + grant {
              + permission = (known after apply)

              + grantee {
                  + display_name  = (known after apply)
                  + email_address = (known after apply)
                  + id            = (known after apply)
                  + type          = (known after apply)
                  + uri           = (known after apply)
                }
            }

          + owner {
              + display_name = (known after apply)
              + id           = (known after apply)
            }
        }
    }

  # aws_s3_bucket_policy.tfe_data will be created
  + resource "aws_s3_bucket_policy" "tfe_data" {
      + bucket = (known after apply)
      + id     = (known after apply)
      + policy = (known after apply)
    }

  # aws_s3_bucket_public_access_block.tfe_data will be created
  + resource "aws_s3_bucket_public_access_block" "tfe_data" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

  # aws_s3_bucket_versioning.tfe_data will be created
  + resource "aws_s3_bucket_versioning" "tfe_data" {
      + bucket = (known after apply)
      + id     = (known after apply)

      + versioning_configuration {
          + mfa_delete = (known after apply)
          + status     = "Enabled"
        }
    }

  # aws_secretsmanager_secret.agent_token will be created
  + resource "aws_secretsmanager_secret" "agent_token" {
      + arn                            = (known after apply)
      + description                    = "TFC agent token"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags_all                       = (known after apply)

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret.tfe_license will be created
  + resource "aws_secretsmanager_secret" "tfe_license" {
      + arn                            = (known after apply)
      + description                    = "The TFE license"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags_all                       = (known after apply)

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret.tls_certificate will be created
  + resource "aws_secretsmanager_secret" "tls_certificate" {
      + arn                            = (known after apply)
      + description                    = "TLS certificate"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags_all                       = (known after apply)

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret.tls_key will be created
  + resource "aws_secretsmanager_secret" "tls_key" {
      + arn                            = (known after apply)
      + description                    = "TLS key"
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags_all                       = (known after apply)

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret_version.agent_token will be created
  + resource "aws_secretsmanager_secret_version" "agent_token" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_id      = (known after apply)
      + secret_string  = (sensitive value)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_secretsmanager_secret_version.tfe_license will be created
  + resource "aws_secretsmanager_secret_version" "tfe_license" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_secretsmanager_secret_version.tls_certificate will be created
  + resource "aws_secretsmanager_secret_version" "tls_certificate" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_secretsmanager_secret_version.tls_key will be created
  + resource "aws_secretsmanager_secret_version" "tls_key" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_security_group.internal_sg will be created
  + resource "aws_security_group" "internal_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow outgoing connections"
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow all the icmp types"
              + from_port        = -1
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "icmp"
              + security_groups  = []
              + self             = false
              + to_port          = -1
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow ssh port 22"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = []
              + description      = "Allow ssh port 22 from public security group"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = []
              + description      = "allow Vault HA request forwarding"
              + from_port        = 8201
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 8201
            },
          + {
              + cidr_blocks      = []
              + description      = "allow https port incoming connection from Load balancer"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = []
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 443
            },
          + {
              + cidr_blocks      = []
              + description      = "allow postgres port incoming connections"
              + from_port        = 5432
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 5432
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.lb_sg will be created
  + resource "aws_security_group" "lb_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow outgoing connections"
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow replicated admin port incoming connection"
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 8800
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.public_sg will be created
  + resource "aws_security_group" "public_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow outgoing connections"
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow http port incoming connection"
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "Allow ssh port 22"
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow https port incoming connection"
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = "allow replicated admin port incoming connection"
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 8800
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.redis_sg will be created
  + resource "aws_security_group" "redis_sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = []
              + description      = ""
              + from_port        = 6379
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = (known after apply)
              + self             = false
              + to_port          = 6380
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = (known after apply)
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # aws_subnet.subnet_private1 will be created
  + resource "aws_subnet" "subnet_private1" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-central-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.1.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_subnet.subnet_private2 will be created
  + resource "aws_subnet" "subnet_private2" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-central-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.2.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_subnet.subnet_public1 will be created
  + resource "aws_subnet" "subnet_public1" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-central-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.3.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_subnet.subnet_public2 will be created
  + resource "aws_subnet" "subnet_public2" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-central-1c"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.5.4.0/24"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags_all                                       = (known after apply)
      + vpc_id                                         = (known after apply)
    }

  # aws_vpc.vpc will be created
  + resource "aws_vpc" "vpc" {
      + arn                                  = (known after apply)
      + cidr_block                           = "10.5.0.0/16"
      + default_network_acl_id               = (known after apply)
      + default_route_table_id               = (known after apply)
      + default_security_group_id            = (known after apply)
      + dhcp_options_id                      = (known after apply)
      + enable_classiclink                   = (known after apply)
      + enable_classiclink_dns_support       = (known after apply)
      + enable_dns_hostnames                 = true
      + enable_dns_support                   = true
      + id                                   = (known after apply)
      + instance_tenancy                     = "default"
      + ipv6_association_id                  = (known after apply)
      + ipv6_cidr_block                      = (known after apply)
      + ipv6_cidr_block_network_border_group = (known after apply)
      + main_route_table_id                  = (known after apply)
      + owner_id                             = (known after apply)
      + tags                                 = (known after apply)
      + tags_all                             = (known after apply)
    }

  # aws_vpc_endpoint.s3 will be created
  + resource "aws_vpc_endpoint" "s3" {
      + arn                   = (known after apply)
      + cidr_blocks           = (known after apply)
      + dns_entry             = (known after apply)
      + id                    = (known after apply)
      + ip_address_type       = (known after apply)
      + network_interface_ids = (known after apply)
      + owner_id              = (known after apply)
      + policy                = (known after apply)
      + prefix_list_id        = (known after apply)
      + private_dns_enabled   = false
      + requester_managed     = (known after apply)
      + route_table_ids       = (known after apply)
      + security_group_ids    = (known after apply)
      + service_name          = "com.amazonaws.eu-central-1.s3"
      + state                 = (known after apply)
      + subnet_ids            = (known after apply)
      + tags_all              = (known after apply)
      + vpc_endpoint_type     = "Gateway"
      + vpc_id                = (known after apply)

      + dns_options {
          + dns_record_ip_type = (known after apply)
        }
    }

  # aws_vpc_endpoint_route_table_association.private_s3_endpoint will be created
  + resource "aws_vpc_endpoint_route_table_association" "private_s3_endpoint" {
      + id              = (known after apply)
      + route_table_id  = (known after apply)
      + vpc_endpoint_id = (known after apply)
    }

  # cloudflare_record.tfe will be created
  + resource "cloudflare_record" "tfe" {
      + allow_overwrite = false
      + created_on      = (known after apply)
      + hostname        = (known after apply)
      + id              = (known after apply)
      + metadata        = (known after apply)
      + modified_on     = (known after apply)
      + name            = (known after apply)
      + proxiable       = (known after apply)
      + ttl             = 1
      + type            = "CNAME"
      + value           = (known after apply)
      + zone_id         = "36b3ef5080f2c6f91e5136854e9f29fb"
    }

  # cloudflare_record.tfe_jump will be created
  + resource "cloudflare_record" "tfe_jump" {
      + allow_overwrite = false
      + created_on      = (known after apply)
      + hostname        = (known after apply)
      + id              = (known after apply)
      + metadata        = (known after apply)
      + modified_on     = (known after apply)
      + name            = (known after apply)
      + proxiable       = (known after apply)
      + ttl             = 1
      + type            = "A"
      + value           = (known after apply)
      + zone_id         = "36b3ef5080f2c6f91e5136854e9f29fb"
    }

  # random_id.archivist_token will be created
  + resource "random_id" "archivist_token" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.cookie_hash will be created
  + resource "random_id" "cookie_hash" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.enc_password will be created
  + resource "random_id" "enc_password" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.install_id will be created
  + resource "random_id" "install_id" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.internal_api_token will be created
  + resource "random_id" "internal_api_token" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.redis_password will be created
  + resource "random_id" "redis_password" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.registry_session_encryption_key will be created
  + resource "random_id" "registry_session_encryption_key" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.registry_session_secret_key will be created
  + resource "random_id" "registry_session_secret_key" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.root_secret will be created
  + resource "random_id" "root_secret" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_id.user_token will be created
  + resource "random_id" "user_token" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # random_string.friendly_name will be created
  + resource "random_string" "friendly_name" {
      + id          = (known after apply)
      + length      = 4
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = (known after apply)
      + numeric     = false
      + result      = (known after apply)
      + special     = false
      + upper       = false
    }

  # random_string.password will be created
  + resource "random_string" "password" {
      + id          = (known after apply)
      + length      = 16
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = true
    }

  # random_string.pgsql_password will be created
  + resource "random_string" "pgsql_password" {
      + id          = (known after apply)
      + length      = 24
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = true
    }

Plan: 66 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + aws_active_agents_ips          = (known after apply)
  + aws_jump_hostname              = (known after apply)
  + aws_jump_public_ip             = (known after apply)
  + aws_lb_active_target_group_ips = (known after apply)
  + ssh_key_name                   = "aakulov"
  + url                            = (known after apply)
random_id.cookie_hash: Creating...
random_id.registry_session_encryption_key: Creating...
random_id.user_token: Creating...
random_id.install_id: Creating...
random_id.registry_session_secret_key: Creating...
random_id.redis_password: Creating...
random_id.enc_password: Creating...
random_string.password: Creating...
random_string.friendly_name: Creating...
random_id.cookie_hash: Creation complete after 0s [id=rM6F1H0eAE-vPxTjZL8zdQ]
random_id.registry_session_secret_key: Creation complete after 0s [id=Hh_1wlvBPjESC7m911DlaA]
random_id.install_id: Creation complete after 0s [id=letxr9aF-cj81IvOqokedA]
random_string.pgsql_password: Creating...
random_id.enc_password: Creation complete after 0s [id=s3hm06RjQ-ODEfU7hRKesg]
random_string.friendly_name: Creation complete after 0s [id=oxsq]
random_string.password: Creation complete after 0s [id=aYCtzdgMJuH0SCOg]
random_id.redis_password: Creation complete after 0s [id=vLxeohERL4aWgpRlJdoNTA]
random_id.user_token: Creation complete after 0s [id=J7jIxZzS9PxGpIpnyGvMQA]
random_id.internal_api_token: Creating...
random_id.archivist_token: Creating...
random_id.root_secret: Creating...
random_string.pgsql_password: Creation complete after 0s [id=NZrr6I1kVUzAqQa4uE6NzY2N]
random_id.registry_session_encryption_key: Creation complete after 0s [id=RqYROmb2xe6t-8vNpqlbdQ]
random_id.internal_api_token: Creation complete after 0s [id=nNeEhueESJNvgxBfgdDxKg]
random_id.archivist_token: Creation complete after 0s [id=VAsFrDa5bxK-cF9RLO9XVA]
random_id.root_secret: Creation complete after 0s [id=AapbLvvHvLJmv3IHnToDrw]
aws_secretsmanager_secret.tls_certificate: Creating...
aws_secretsmanager_secret.agent_token: Creating...
aws_secretsmanager_secret.tls_key: Creating...
aws_secretsmanager_secret.tfe_license: Creating...
aws_vpc.vpc: Creating...
aws_iam_role.instance_role: Creating...
aws_acm_certificate.tfe: Creating...
aws_s3_bucket.tfe_data: Creating...
aws_secretsmanager_secret.tls_certificate: Creation complete after 1s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-oxsq-tfe_certificate-LvWvff]
aws_secretsmanager_secret.tls_key: Creation complete after 1s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-oxsq-tfe_key-nLGQnn]
aws_secretsmanager_secret.agent_token: Creation complete after 1s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-oxsq-agent_token-RHbHKk]
aws_secretsmanager_secret.tfe_license: Creation complete after 1s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-oxsq-tfe_license-9tNYmf]
aws_secretsmanager_secret_version.tls_certificate: Creating...
aws_secretsmanager_secret_version.agent_token: Creating...
aws_secretsmanager_secret_version.tls_key: Creating...
aws_secretsmanager_secret_version.tfe_license: Creating...
aws_secretsmanager_secret_version.tls_certificate: Creation complete after 0s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-oxsq-tfe_certificate-LvWvff|62DD50B6-A268-4EB1-A2F7-898615B91601]
aws_secretsmanager_secret_version.tls_key: Creation complete after 0s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-oxsq-tfe_key-nLGQnn|CA454A10-8759-43AE-ACD8-2D3D8B84EBED]
aws_secretsmanager_secret_version.agent_token: Creation complete after 0s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-oxsq-agent_token-RHbHKk|C29104C1-1FA1-4FD7-BE75-EFB79B44BC97]
aws_acm_certificate.tfe: Creation complete after 1s [id=arn:aws:acm:eu-central-1:267023797923:certificate/024c34e9-b7fa-4448-9b81-d479b0d31bb2]
aws_secretsmanager_secret_version.tfe_license: Creation complete after 0s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-oxsq-tfe_license-9tNYmf|3BD49E9F-E32C-49C8-AA49-EA7C395F90F7]
data.aws_iam_policy_document.secretsmanager: Reading...
data.aws_iam_policy_document.secretsmanager: Read complete after 0s [id=3934404111]
aws_iam_role.instance_role: Creation complete after 2s [id=aakulov-oxsq-tfe20220823062757097800000001]
aws_iam_role_policy.secretsmanager: Creating...
aws_iam_role_policy.tfe_asg_discovery: Creating...
aws_iam_instance_profile.tfe: Creating...
aws_s3_bucket.tfe_data: Creation complete after 2s [id=aakulov-oxsq-tfe-data]
aws_s3_bucket_public_access_block.tfe_data: Creating...
aws_s3_bucket_acl.tfe_data: Creating...
aws_s3_bucket_versioning.tfe_data: Creating...
data.aws_iam_policy_document.tfe_data: Reading...
data.aws_iam_policy_document.tfe_data: Read complete after 0s [id=2455084902]
aws_s3_bucket_public_access_block.tfe_data: Creation complete after 0s [id=aakulov-oxsq-tfe-data]
aws_iam_role_policy.secretsmanager: Creation complete after 0s [id=aakulov-oxsq-tfe20220823062757097800000001:aakulov-oxsq-tfe-secretsmanager]
aws_iam_role_policy.tfe_asg_discovery: Creation complete after 0s [id=aakulov-oxsq-tfe20220823062757097800000001:aakulov-oxsq-tfe-asg-discovery]
aws_s3_bucket_policy.tfe_data: Creating...
aws_s3_bucket_acl.tfe_data: Creation complete after 0s [id=aakulov-oxsq-tfe-data,private]
aws_iam_instance_profile.tfe: Creation complete after 0s [id=aakulov-oxsq-tfe20220823062758550000000002]
aws_s3_bucket_versioning.tfe_data: Creation complete after 2s [id=aakulov-oxsq-tfe-data]
aws_vpc.vpc: Still creating... [10s elapsed]
aws_s3_bucket_policy.tfe_data: Creation complete after 8s [id=aakulov-oxsq-tfe-data]
aws_vpc.vpc: Creation complete after 12s [id=vpc-00e8491c2b03e9ca4]
aws_internet_gateway.igw: Creating...
aws_subnet.subnet_public1: Creating...
aws_subnet.subnet_private1: Creating...
aws_subnet.subnet_private2: Creating...
aws_subnet.subnet_public2: Creating...
aws_vpc_endpoint.s3: Creating...
aws_lb_target_group.tfe_443: Creating...
aws_security_group.lb_sg: Creating...
aws_security_group.public_sg: Creating...
aws_internet_gateway.igw: Creation complete after 0s [id=igw-015e1ea5498d56ee0]
aws_eip.aws_nat: Creating...
aws_route_table.public: Creating...
aws_subnet.subnet_private1: Creation complete after 0s [id=subnet-06dafc8c0dbdc3f89]
aws_subnet.subnet_private2: Creation complete after 0s [id=subnet-0f8b3dd4261525545]
aws_subnet.subnet_public1: Creation complete after 0s [id=subnet-09691f91cc2b014dd]
aws_subnet.subnet_public2: Creation complete after 0s [id=subnet-0d869c228fa480795]
aws_elasticache_subnet_group.tfe: Creating...
aws_db_subnet_group.tfe: Creating...
aws_eip.aws_nat: Creation complete after 1s [id=eipalloc-01270360f240c7393]
aws_nat_gateway.nat: Creating...
aws_lb_target_group.tfe_443: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:targetgroup/aakulov-oxsq-tfe-tg-443/0418f6d809700e3a]
aws_route_table.public: Creation complete after 1s [id=rtb-0830d83016bb32c81]
aws_route_table_association.public1: Creating...
aws_route_table_association.public2: Creating...
aws_elasticache_subnet_group.tfe: Creation complete after 1s [id=aakulov-oxsq-tfe-redis]
aws_route_table_association.public2: Creation complete after 0s [id=rtbassoc-0e6c44239bb14f2ff]
aws_route_table_association.public1: Creation complete after 1s [id=rtbassoc-0b95baf58c224900c]
aws_db_subnet_group.tfe: Creation complete after 2s [id=aakulov-oxsq-db-subnet]
aws_security_group.lb_sg: Creation complete after 2s [id=sg-0b5a39e32bc67137d]
aws_security_group.public_sg: Creation complete after 2s [id=sg-082d4c069b18f1a0e]
aws_lb.tfe_lb: Creating...
aws_instance.ssh_jump: Creating...
aws_security_group.internal_sg: Creating...
aws_security_group.internal_sg: Creation complete after 2s [id=sg-0ba6f20d9cbefb1ba]
data.aws_instances.tfc_agent: Reading...
data.aws_instances.tfe: Reading...
aws_launch_configuration.tfc_agent: Creating...
aws_security_group.redis_sg: Creating...
aws_db_instance.tfe: Creating...
data.aws_instances.tfc_agent: Read complete after 0s [id=eu-central-1]
data.aws_instances.tfe: Read complete after 0s [id=eu-central-1]
aws_launch_configuration.tfc_agent: Creation complete after 1s [id=aakulov-oxsq-tfc_agent-launch-configuration20220823062812897200000003]
aws_autoscaling_group.tfc_agent: Creating...
aws_autoscaling_group.tfc_agent: Creation complete after 0s [id=aakulov-oxsq-asg-tfc_agent]
aws_vpc_endpoint.s3: Creation complete after 6s [id=vpce-035c6029534b15f32]
aws_security_group.redis_sg: Creation complete after 2s [id=sg-080233b02ca0e27aa]
aws_elasticache_replication_group.redis: Creating...
aws_nat_gateway.nat: Still creating... [10s elapsed]
aws_lb.tfe_lb: Still creating... [10s elapsed]
aws_instance.ssh_jump: Still creating... [10s elapsed]
aws_db_instance.tfe: Still creating... [10s elapsed]
aws_instance.ssh_jump: Creation complete after 12s [id=i-09370cee8e9674fa2]
aws_eip.ssh_jump: Creating...
aws_eip.ssh_jump: Creation complete after 1s [id=eipalloc-0256588d8465170cf]
cloudflare_record.tfe_jump: Creating...
aws_elasticache_replication_group.redis: Still creating... [10s elapsed]
cloudflare_record.tfe_jump: Creation complete after 2s [id=e64a359d165582acd73a8178338af89e]
aws_nat_gateway.nat: Still creating... [20s elapsed]
aws_lb.tfe_lb: Still creating... [20s elapsed]
aws_db_instance.tfe: Still creating... [20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [20s elapsed]
aws_nat_gateway.nat: Still creating... [30s elapsed]
aws_lb.tfe_lb: Still creating... [30s elapsed]
aws_db_instance.tfe: Still creating... [30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [30s elapsed]
aws_nat_gateway.nat: Still creating... [40s elapsed]
aws_lb.tfe_lb: Still creating... [40s elapsed]
aws_db_instance.tfe: Still creating... [40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [40s elapsed]
aws_nat_gateway.nat: Still creating... [50s elapsed]
aws_lb.tfe_lb: Still creating... [50s elapsed]
aws_db_instance.tfe: Still creating... [50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [50s elapsed]
aws_nat_gateway.nat: Still creating... [1m0s elapsed]
aws_lb.tfe_lb: Still creating... [1m0s elapsed]
aws_db_instance.tfe: Still creating... [1m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m0s elapsed]
aws_nat_gateway.nat: Still creating... [1m10s elapsed]
aws_lb.tfe_lb: Still creating... [1m10s elapsed]
aws_db_instance.tfe: Still creating... [1m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m10s elapsed]
aws_nat_gateway.nat: Still creating... [1m20s elapsed]
aws_lb.tfe_lb: Still creating... [1m20s elapsed]
aws_db_instance.tfe: Still creating... [1m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m20s elapsed]
aws_nat_gateway.nat: Still creating... [1m30s elapsed]
aws_lb.tfe_lb: Still creating... [1m30s elapsed]
aws_db_instance.tfe: Still creating... [1m30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m30s elapsed]
aws_nat_gateway.nat: Still creating... [1m40s elapsed]
aws_lb.tfe_lb: Still creating... [1m40s elapsed]
aws_db_instance.tfe: Still creating... [1m40s elapsed]
aws_nat_gateway.nat: Creation complete after 1m44s [id=nat-01c7c739f61e58dbf]
aws_route_table.private: Creating...
aws_elasticache_replication_group.redis: Still creating... [1m40s elapsed]
aws_route_table.private: Creation complete after 1s [id=rtb-023b9be0d903f1da2]
aws_vpc_endpoint_route_table_association.private_s3_endpoint: Creating...
aws_route_table_association.private2: Creating...
aws_route_table_association.private1: Creating...
aws_route_table_association.private2: Creation complete after 0s [id=rtbassoc-02856474436508314]
aws_route_table_association.private1: Creation complete after 0s [id=rtbassoc-0067b687b2d103909]
aws_vpc_endpoint_route_table_association.private_s3_endpoint: Creation complete after 1s [id=a-vpce-035c6029534b15f321537949281]
aws_lb.tfe_lb: Still creating... [1m50s elapsed]
aws_db_instance.tfe: Still creating... [1m50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [1m50s elapsed]
aws_lb.tfe_lb: Still creating... [2m0s elapsed]
aws_lb.tfe_lb: Creation complete after 2m1s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:loadbalancer/app/aakulov-oxsq-tfe-app-lb/960a5599a5cf1dec]
cloudflare_record.tfe: Creating...
aws_lb_listener.lb_443: Creating...
aws_lb_listener.lb_443: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:listener/app/aakulov-oxsq-tfe-app-lb/960a5599a5cf1dec/f0aada9b9e97fdc5]
aws_db_instance.tfe: Still creating... [2m0s elapsed]
cloudflare_record.tfe: Creation complete after 2s [id=535d8123e23c5ba985869c47bd975555]
aws_elasticache_replication_group.redis: Still creating... [2m0s elapsed]
aws_db_instance.tfe: Still creating... [2m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m10s elapsed]
aws_db_instance.tfe: Still creating... [2m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m20s elapsed]
aws_db_instance.tfe: Still creating... [2m30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m30s elapsed]
aws_db_instance.tfe: Still creating... [2m40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m40s elapsed]
aws_db_instance.tfe: Still creating... [2m50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [2m50s elapsed]
aws_db_instance.tfe: Creation complete after 2m53s [id=terraform-20220823062812899500000004]
aws_elasticache_replication_group.redis: Still creating... [3m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [3m50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [4m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [4m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [4m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [4m30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [4m40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [4m50s elapsed]
aws_elasticache_replication_group.redis: Still creating... [5m0s elapsed]
aws_elasticache_replication_group.redis: Still creating... [5m10s elapsed]
aws_elasticache_replication_group.redis: Still creating... [5m20s elapsed]
aws_elasticache_replication_group.redis: Still creating... [5m30s elapsed]
aws_elasticache_replication_group.redis: Still creating... [5m40s elapsed]
aws_elasticache_replication_group.redis: Still creating... [5m50s elapsed]
aws_elasticache_replication_group.redis: Creation complete after 5m58s [id=aakulov-oxsq-tfe]
aws_launch_configuration.tfe: Creating...
aws_launch_configuration.tfe: Creation complete after 2s [id=aakulov-oxsq-tfe-launch-configuration20220823063413240900000005]
aws_autoscaling_group.tfe: Creating...
aws_autoscaling_group.tfe: Still creating... [10s elapsed]
aws_autoscaling_group.tfe: Still creating... [20s elapsed]
aws_autoscaling_group.tfe: Creation complete after 28s [id=aakulov-oxsq-tfe-asg]

Apply complete! Resources: 66 added, 0 changed, 0 destroyed.

Outputs:

aws_active_agents_ips = ""
aws_jump_hostname = "oxsqtfeaajump.akulov.cc"
aws_jump_public_ip = "3.72.235.5"
aws_lb_active_target_group_ips = ""
ssh_key_name = "aakulov"
url = "https://oxsqtfeaa.akulov.cc/admin/account/new?token=xxxxxxxxxxxxxxxxx"

```

## Generate agent token

- Open the `url` received from `terraform output`

![Open the url](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen1.png)

- Fill the Username, Email, Password and click `Create an account`

![Create admin user](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen2.png)

Expected result:

![Created admin user](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen3.png)

- Type organisation name and click `Create organisation`

![Create organisation](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen4.png)

Expected result:

![Created organisation](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen5.png)

- Click `CLI driven workflow`

- Type workspace name and click `Create workspace`

![Create workspace](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen6.png)

- Click `Settings - General`

![Settings - General](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen7.png)

- Click Agents

![Agents](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen8.png)

- Click `Create agent pool`

![Create agent pool](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen9.png)

Expected result

![Created agent pool](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen10.png)

- Type token name. Click `Create token`

![Create token](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen11.png)

Expected result

![Created token](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen12.png)

- Copy generated token and paste to the `terraform.tfvars` variable `agent_token` value

```
agent_token             = "xxxxxxxxxxxxxxxx"
```

- Open previously created workspace

![Workspace](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen13.png)

- Click `General`

![General](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen14.png)

- Click `Agent`

![Agent](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen15.png)

Expected result

![Clicked agent](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen16.png)

- Click `Save settings`

![Save settings](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen17.png)

- Set number of agents in the `terraform.tfvars` file

```
asg_min_agents          = 2
asg_max_agents          = 2
asg_desired_agents      = 2
```

- Run the `terraform apply`

Expected result:

```
% terraform apply  --auto-approve
random_id.cookie_hash: Refreshing state... [id=3HiRcMPmsPuFmMED5l9fmQ]
random_id.internal_api_token: Refreshing state... [id=9mxDQomSe28gtF0C9AvRnw]
random_id.archivist_token: Refreshing state... [id=hg9njhO5qljKTM1rgTngFA]
random_string.friendly_name: Refreshing state... [id=kpim]
random_id.enc_password: Refreshing state... [id=c2gXFoarO1DsIpzxmwU1bw]
random_string.pgsql_password: Refreshing state... [id=IQPNwTC4kFzejV0HWuQbKum6]
data.local_sensitive_file.sslkey: Reading...
data.local_sensitive_file.sslchain: Reading...
random_id.registry_session_secret_key: Refreshing state... [id=-8LLb_st96RgSgs_zRu-YA]
data.local_sensitive_file.sslchain: Read complete after 0s [id=35bea03aecd55ca4d525c6b0a45908a19c6986f9]
data.local_sensitive_file.sslkey: Read complete after 0s [id=c55e3e91058bd74118c719cdb13ae552d5b3347c]
random_id.redis_password: Refreshing state... [id=DCL6Rx7kCG2wGbGDOp3V3Q]
random_id.root_secret: Refreshing state... [id=2iwsGUSazRLmZiSPG9YLGA]
data.local_sensitive_file.sslcert: Reading...
random_id.registry_session_encryption_key: Refreshing state... [id=CRzQ210BESzw2OlcQnX9kw]
random_id.user_token: Refreshing state... [id=BZtCN-qqj9kcBLFkrGKgXg]
random_id.install_id: Refreshing state... [id=48FfH4QpPL-5_bvIf35F7Q]
random_string.password: Refreshing state... [id=lqmdhdHtRZrjFOWk]
data.local_sensitive_file.sslcert: Read complete after 0s [id=03a1061535e45b575f310a070f77ab6ba7c314f0]
data.aws_iam_policy_document.instance_role: Reading...
aws_vpc.vpc: Refreshing state... [id=vpc-0943a45d8f68cc4ec]
aws_secretsmanager_secret.agent_token: Refreshing state... [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-agent_token-A4NZrc]
data.aws_iam_policy_document.tfe_asg_discovery: Reading...
aws_secretsmanager_secret.tls_key: Refreshing state... [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_key-2Hpam1]
aws_secretsmanager_secret.tfe_license: Refreshing state... [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_license-L4JdYe]
aws_secretsmanager_secret.tls_certificate: Refreshing state... [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_certificate-t69C9f]
data.aws_iam_policy_document.instance_role: Read complete after 0s [id=1903849331]
data.aws_iam_policy_document.tfe_asg_discovery: Read complete after 0s [id=139118870]
aws_acm_certificate.tfe: Refreshing state... [id=arn:aws:acm:eu-central-1:267023797923:certificate/34f24234-ea4b-4a7e-bdae-2be7b94b6f3c]
aws_s3_bucket.tfe_data: Refreshing state... [id=aakulov-kpim-tfe-data]
aws_iam_role.instance_role: Refreshing state... [id=aakulov-kpim-tfe20220823072954902800000001]
aws_secretsmanager_secret_version.tfe_license: Refreshing state... [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_license-L4JdYe|19BA5A96-63EE-45B6-A096-3942050CD378]
aws_secretsmanager_secret_version.tls_key: Refreshing state... [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_key-2Hpam1|23A9C878-D200-4F62-8549-777F135DD2D3]
aws_secretsmanager_secret_version.tls_certificate: Refreshing state... [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_certificate-t69C9f|E9788C9A-4C82-48A4-8791-F7C2538E6B4A]
aws_secretsmanager_secret_version.agent_token: Refreshing state... [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-agent_token-A4NZrc|DA0ACC39-03B2-4C08-90CC-D60836AC61F3]
aws_internet_gateway.igw: Refreshing state... [id=igw-02ab0eb390f04d256]
aws_subnet.subnet_private1: Refreshing state... [id=subnet-011ed6839f572bc3a]
aws_subnet.subnet_private2: Refreshing state... [id=subnet-02c8bc21df946498a]
aws_vpc_endpoint.s3: Refreshing state... [id=vpce-0c00ceb9d6c383f03]
aws_subnet.subnet_public2: Refreshing state... [id=subnet-0674c7dd985f414f7]
aws_lb_target_group.tfe_443: Refreshing state... [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:targetgroup/aakulov-kpim-tfe-tg-443/b81fe85249dd83e8]
aws_security_group.lb_sg: Refreshing state... [id=sg-0dbd5c0279cdd1e8a]
aws_security_group.public_sg: Refreshing state... [id=sg-0a2b658aba0496385]
aws_subnet.subnet_public1: Refreshing state... [id=subnet-0bb2a7807aa612c1e]
aws_s3_bucket_public_access_block.tfe_data: Refreshing state... [id=aakulov-kpim-tfe-data]
aws_s3_bucket_versioning.tfe_data: Refreshing state... [id=aakulov-kpim-tfe-data]
aws_s3_bucket_acl.tfe_data: Refreshing state... [id=aakulov-kpim-tfe-data,private]
aws_eip.aws_nat: Refreshing state... [id=eipalloc-02fab908de09cb94d]
aws_route_table.public: Refreshing state... [id=rtb-0f6885cc8d8a96d31]
aws_db_subnet_group.tfe: Refreshing state... [id=aakulov-kpim-db-subnet]
aws_elasticache_subnet_group.tfe: Refreshing state... [id=aakulov-kpim-tfe-redis]
aws_security_group.internal_sg: Refreshing state... [id=sg-0d4bf554921d80f67]
aws_lb.tfe_lb: Refreshing state... [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:loadbalancer/app/aakulov-kpim-tfe-app-lb/6a73e5b4dbb1c875]
aws_instance.ssh_jump: Refreshing state... [id=i-05d122f1e97500b47]
aws_nat_gateway.nat: Refreshing state... [id=nat-0f189ded3bd4341ef]
aws_route_table_association.public2: Refreshing state... [id=rtbassoc-07ab2e35d67ddbd05]
aws_route_table_association.public1: Refreshing state... [id=rtbassoc-0976891b7ddd7596f]
data.aws_instances.tfc_agent: Reading...
data.aws_instances.tfe: Reading...
aws_security_group.redis_sg: Refreshing state... [id=sg-0f178db1fcf759c9b]
data.aws_instances.tfc_agent: Read complete after 0s [id=eu-central-1]
aws_route_table.private: Refreshing state... [id=rtb-0207c74b54b845b21]
cloudflare_record.tfe: Refreshing state... [id=5ac925d0ea0aca1bd5d159d6a5a99450]
aws_lb_listener.lb_443: Refreshing state... [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:listener/app/aakulov-kpim-tfe-app-lb/6a73e5b4dbb1c875/60612893c6b65ddd]
aws_route_table_association.private2: Refreshing state... [id=rtbassoc-0e5982c3f642771fe]
aws_route_table_association.private1: Refreshing state... [id=rtbassoc-0bc940402a47f991d]
data.aws_instances.tfe: Read complete after 0s [id=eu-central-1]
aws_vpc_endpoint_route_table_association.private_s3_endpoint: Refreshing state... [id=a-vpce-0c00ceb9d6c383f032611001832]
aws_db_instance.tfe: Refreshing state... [id=terraform-20220823073011343000000004]
aws_elasticache_replication_group.redis: Refreshing state... [id=aakulov-kpim-tfe]
aws_iam_role_policy.tfe_asg_discovery: Refreshing state... [id=aakulov-kpim-tfe20220823072954902800000001:aakulov-kpim-tfe-asg-discovery]
aws_iam_role_policy.secretsmanager: Refreshing state... [id=aakulov-kpim-tfe20220823072954902800000001:aakulov-kpim-tfe-secretsmanager]
aws_iam_instance_profile.tfe: Refreshing state... [id=aakulov-kpim-tfe20220823072956569100000002]
data.aws_iam_policy_document.tfe_data: Reading...
data.aws_iam_policy_document.tfe_data: Read complete after 0s [id=1179488468]
aws_s3_bucket_policy.tfe_data: Refreshing state... [id=aakulov-kpim-tfe-data]
aws_launch_configuration.tfc_agent: Refreshing state... [id=aakulov-kpim-tfc_agent-launch-configuration20220823075047794200000001]
aws_eip.ssh_jump: Refreshing state... [id=eipalloc-042bfa59228691629]
cloudflare_record.tfe_jump: Refreshing state... [id=8a5a429ead20add931bc5abcbd66ea77]
aws_autoscaling_group.tfc_agent: Refreshing state... [id=aakulov-kpim-asg-tfc_agent]
aws_launch_configuration.tfe: Refreshing state... [id=aakulov-kpim-tfe-launch-configuration20220823073613544500000005]
aws_autoscaling_group.tfe: Refreshing state... [id=aakulov-kpim-tfe-asg]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  ~ update in-place
-/+ destroy and then create replacement
 <= read (data resources)

Terraform will perform the following actions:

  # data.aws_iam_policy_document.secretsmanager will be read during apply
  # (depends on a resource or a module with changes pending)
 <= data "aws_iam_policy_document" "secretsmanager" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "secretsmanager:GetSecretValue",
            ]
          + effect    = "Allow"
          + resources = [
              + "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-agent_token-A4NZrc",
              + "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_certificate-t69C9f",
              + "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_key-2Hpam1",
              + "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_license-L4JdYe",
            ]
          + sid       = "AllowSecretsManagerSecretAccess"
        }
    }

  # aws_autoscaling_group.tfc_agent will be updated in-place
  ~ resource "aws_autoscaling_group" "tfc_agent" {
      ~ desired_capacity          = 0 -> 2
        id                        = "aakulov-kpim-asg-tfc_agent"
      ~ max_size                  = 0 -> 2
      ~ min_size                  = 0 -> 2
        name                      = "aakulov-kpim-asg-tfc_agent"
        # (21 unchanged attributes hidden)

        # (1 unchanged block hidden)
    }

  # aws_iam_role_policy.secretsmanager will be updated in-place
  ~ resource "aws_iam_role_policy" "secretsmanager" {
        id     = "aakulov-kpim-tfe20220823072954902800000001:aakulov-kpim-tfe-secretsmanager"
        name   = "aakulov-kpim-tfe-secretsmanager"
      ~ policy = jsonencode(
            {
              - Statement = [
                  - {
                      - Action   = "secretsmanager:GetSecretValue"
                      - Effect   = "Allow"
                      - Resource = [
                          - "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_license-L4JdYe",
                          - "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_key-2Hpam1",
                          - "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-tfe_certificate-t69C9f",
                          - "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-agent_token-A4NZrc",
                        ]
                      - Sid      = "AllowSecretsManagerSecretAccess"
                    },
                ]
              - Version   = "2012-10-17"
            }
        ) -> (known after apply)
        # (1 unchanged attribute hidden)
    }

  # aws_secretsmanager_secret_version.agent_token must be replaced
-/+ resource "aws_secretsmanager_secret_version" "agent_token" {
      ~ arn            = "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-agent_token-A4NZrc" -> (known after apply)
      ~ id             = "arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-agent_token-A4NZrc|DA0ACC39-03B2-4C08-90CC-D60836AC61F3" -> (known after apply)
      ~ secret_string  = (sensitive value) # forces replacement
      ~ version_id     = "DA0ACC39-03B2-4C08-90CC-D60836AC61F3" -> (known after apply)
      ~ version_stages = [
          - "AWSCURRENT",
        ] -> (known after apply)
        # (1 unchanged attribute hidden)
    }

Plan: 1 to add, 2 to change, 1 to destroy.
aws_secretsmanager_secret_version.agent_token: Destroying... [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-agent_token-A4NZrc|DA0ACC39-03B2-4C08-90CC-D60836AC61F3]
aws_secretsmanager_secret_version.agent_token: Destruction complete after 0s
aws_secretsmanager_secret_version.agent_token: Creating...
aws_autoscaling_group.tfc_agent: Modifying... [id=aakulov-kpim-asg-tfc_agent]
aws_secretsmanager_secret_version.agent_token: Creation complete after 1s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:aakulov-kpim-agent_token-A4NZrc|178624B9-56ED-4CEB-83F4-44A9D8B46D3E]
data.aws_iam_policy_document.secretsmanager: Reading...
data.aws_iam_policy_document.secretsmanager: Read complete after 0s [id=1879410054]
aws_autoscaling_group.tfc_agent: Still modifying... [id=aakulov-kpim-asg-tfc_agent, 10s elapsed]
aws_autoscaling_group.tfc_agent: Still modifying... [id=aakulov-kpim-asg-tfc_agent, 20s elapsed]
aws_autoscaling_group.tfc_agent: Modifications complete after 27s [id=aakulov-kpim-asg-tfc_agent]

Apply complete! Resources: 1 added, 1 changed, 1 destroyed.

Outputs:

aws_active_agents_ips = ""
aws_jump_hostname = "kpimtfeaajump.akulov.cc"
aws_jump_public_ip = "3.125.78.59"
aws_lb_active_target_group_ips = "10.5.1.30, 10.5.2.203"
ssh_key_name = "aakulov"
url = "https://kpimtfeaa.akulov.cc/admin/account/new?token=xxxxxxxxx"

```

- Click `Settings - Agents`

Expected result:

![Agents](https://github.com/antonakv/tf-aws-activeactive-agents/raw/main/images/screen18.png)
