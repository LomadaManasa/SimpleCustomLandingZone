resource "aws_organizations_organization" "Root" {
  feature_set = "ALL"
  enabled_policy_types = [
    "SERVICE_CONTROL_POLICY"
  ]
  aws_service_access_principals = [
    "sso.amazonaws.com"
  ]
}
resource "aws_organizations_organizational_unit" "Dev" {
  name      = "Dev"
  parent_id = aws_organizations_organization.Root.roots.0.id
}
resource "aws_organizations_account" "member_accounts" {
  
  name         = "Naveen"
  email       = "rajendrangopal97@gmail.com"
  parent_id = aws_organizations_organizational_unit.Dev.id
}
resource "aws_iam_role" "scp_management_role" {
  name = "SCPManagementRole1"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = aws_organizations_organization.Root.master_account_id
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}
# Create an IAM Policy for managing SCPs
resource "aws_iam_policy" "scp_management_policy" {
  name        = "SCPManagementPolicy1"
  description = "Policy for managing SCPs"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "organizations:AttachPolicy"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "organizations:DescribePolicy"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "organizations:CreatePolicy"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "organizations:UpdatePolicy"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "organizations:DeletePolicy"
        Resource = "*"
      }
    ]
  })
}

# Attach the IAM Policy to the IAM Role
resource "aws_iam_role_policy_attachment" "scp_management_attachment" {
  policy_arn = aws_iam_policy.scp_management_policy.arn
  role       = aws_iam_role.scp_management_role.name
}
resource "aws_organizations_policy" "cw_policy" {
    name = "cloudwatch-retention-policy"
    description = "Enforce a retention period for CloudWatch logs"
    content = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Sid = "CloudWatchRetention"
                Effect = "Deny"
                Action = [
                    "logs:PutRetentionPolicy"
                    ]
                Resource = "*" 
                Condition = {
                    NumericGreaterThanEquals = {
                        "logs:retentionInDays": 15 # Change to desired retention period
                        }
                    }
            },
            {
                Sid = "cwalertmodification"
                Effect = "Deny"
                Action = [
                    "cloudwatch:DeleteAlarms",
                    "cloudwatch:DeleteDashboards",
                    "cloudwatch:DisableAlarmActions",
                    "cloudwatch:PutDashboard",
                    "cloudwatch:PutMetricAlarm",
                    "cloudwatch:SetAlarmState"
                ]
                Resource = "*"
            }

        ]
    })
}
resource "aws_organizations_policy" "scp" {
  name        = "MySCPPolicy1"
  description = "My custom SCP policy"

  content = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*",
        "Condition": {
          "StringNotEqualsIfExists": {
            /*"aws:PrincipalArn": [
              "arn:aws:iam::${aws_organizations_account.child.id}:root"
            ]*/
          }
        }
      }
    ]
  })
}


resource "aws_organizations_policy_attachment" "scp_attachment" {
  policy_id = aws_organizations_policy.scp.id
  target_id = aws_organizations_account.member_accounts.id
}
resource "aws_organizations_policy_attachment" "cw_policy_attachment" {
  policy_id = aws_organizations_policy.cw_policy.id
  target_id = aws_organizations_account.member_accounts.id
}
data "aws_ssoadmin_instances" "testSSO" {}

resource "aws_ssoadmin_permission_set" "sso_permissions" {
  instance_arn     = tolist(data.aws_ssoadmin_instances.testSSO.arns)[0]
  name             = "MySSOPermissionSet"
  description      = "My SSO permission set"
  session_duration = "PT1H" # Optional: Set session duration
}
resource "aws_iam_policy" "admin_policy" {
  name   = "SSOAdminPolicy"
  policy = data.aws_iam_policy_document.admin_policy.json
}

data "aws_iam_policy_document" "admin_policy" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
resource "aws_ssoadmin_permission_set_inline_policy" "sso_permissions_inline_policy" {
  inline_policy = data.aws_iam_policy_document.admin_policy.json
  permission_set_arn = aws_ssoadmin_permission_set.sso_permissions.arn
  instance_arn = tolist(data.aws_ssoadmin_instances.testSSO.arns)[0]
}
data "aws_identitystore_group" "TestGroup" {
  identity_store_id = tolist(data.aws_ssoadmin_instances.testSSO.identity_store_ids)[0]
  alternate_identifier {
    unique_attribute {
      attribute_path  = "DisplayName"
      attribute_value = "TestGroup"
    }
  }
}
resource "aws_ssoadmin_account_assignment" "example_assignment" {
 instance_arn = tolist(data.aws_ssoadmin_instances.testSSO.arns)[0]
 permission_set_arn = aws_ssoadmin_permission_set.sso_permissions.arn
 principal_id = data.aws_identitystore_group.TestGroup.id
 principal_type = "GROUP"
 target_id = aws_organizations_account.member_accounts.id
 target_type = "AWS_ACCOUNT"
}

