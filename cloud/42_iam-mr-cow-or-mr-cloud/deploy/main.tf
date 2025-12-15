terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Allow public bucket policies in this account (needed for the public storefront asset).
data "aws_caller_identity" "me" {}

resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}

# ================
# SECRET BUCKET
# ================
resource "aws_s3_bucket" "secret" {
  bucket = var.secret_bucket_name
}

resource "aws_s3_bucket_ownership_controls" "secret_own" {
  bucket = aws_s3_bucket.secret.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_public_access_block" "secret_pab" {
  bucket                  = aws_s3_bucket.secret.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
}

# Policy:
# - Public may GetObject for assets/* (so the icon stays world-readable)
# - Describe actions:
#     Allow any *MrCow principal to inspect the bucket policy and ACL
# - ListBucket:
#     Allow only *MrCow principals (by username suffix); deny everyone else
# - GetObject (flag.txt):
#     Allow only *MrCloud principals (by username suffix); deny everyone else
resource "aws_s3_bucket_policy" "secret_policy" {
  bucket = aws_s3_bucket.secret.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      # Public read of assets (icon only)
      {
        Sid       = "PublicReadAssets",
        Effect    = "Allow",
        Principal = "*",
        Action    = ["s3:GetObject"],
        Resource  = "${aws_s3_bucket.secret.arn}/assets/*"
      },

      # ===== BUCKET INSPECTION =====
      {
        Sid       = "AllowPublicPolicyRead",
        Effect    = "Allow",
        Principal = "*",
        Action    = ["s3:GetBucketPolicy"],
        Resource  = aws_s3_bucket.secret.arn
      },

      {
        Sid       = "AllowDescribeForMrCow",
        Effect    = "Allow",
        Principal = "*",
        Action = [
          "s3:GetBucketLocation",
          "s3:GetBucketAcl"
        ],
        Resource = aws_s3_bucket.secret.arn,
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:user/*MrCow"
          }
        }
      },

      # ===== LIST BUCKET =====
      {
        Sid       = "AllowListForMrCow",
        Effect    = "Allow",
        Principal = "*",
        Action    = ["s3:ListBucket"],
        Resource  = aws_s3_bucket.secret.arn,
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:user/*MrCow"
          }
        }
      },
      {
        Sid       = "DenyListForNonMrCow",
        Effect    = "Deny",
        Principal = "*",
        Action    = ["s3:ListBucket"],
        Resource  = aws_s3_bucket.secret.arn,
        Condition = {
          # Deny if NOT any of these patterns (so your deployer is exempt)
          StringNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:user/*MrCow",
              "arn:aws:iam::${data.aws_caller_identity.me.account_id}:root",
              "arn:aws:iam::${data.aws_caller_identity.me.account_id}:user/*",
              "arn:aws:iam::${data.aws_caller_identity.me.account_id}:role/*",
              "arn:aws:sts::${data.aws_caller_identity.me.account_id}:assumed-role/*/*"
            ]
          }
        }
      },

      # ===== GET FLAG =====
      {
        Sid       = "AllowGetFlagForMrCloud",
        Effect    = "Allow",
        Principal = "*",
        Action    = ["s3:GetObject"],
        Resource  = "${aws_s3_bucket.secret.arn}/flag.txt",
        Condition = {
          StringLike = {
            "aws:PrincipalArn" = "arn:aws:iam::*:user/*MrCloud"
          }
        }
      },
      {
        Sid       = "DenyGetFlagForNonMrCloud",
        Effect    = "Deny",
        Principal = "*",
        Action    = ["s3:GetObject"],
        Resource  = "${aws_s3_bucket.secret.arn}/flag.txt",
        Condition = {
          # Deny if NOT any of these patterns (so your deployer is exempt)
          StringNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::*:user/*MrCloud",
              "arn:aws:iam::${data.aws_caller_identity.me.account_id}:root",
              "arn:aws:iam::${data.aws_caller_identity.me.account_id}:user/*",
              "arn:aws:iam::${data.aws_caller_identity.me.account_id}:role/*",
              "arn:aws:sts::${data.aws_caller_identity.me.account_id}:assumed-role/*/*"
            ]
          }
        }
      }
    ]
  })
}

# ======= Objects =======

# Flag
resource "aws_s3_object" "flag" {
  bucket       = aws_s3_bucket.secret.id
  key          = "flag.txt"
  content      = var.flag_value
  content_type = "text/plain"
}

# Icon
resource "aws_s3_object" "icon_svg" {
  bucket       = aws_s3_bucket.secret.id
  key          = "assets/cowcloud.svg"
  content_type = "image/svg+xml"
  source       = "${path.module}/assets/cowcloud.svg"
  etag         = filemd5("${path.module}/assets/cowcloud.svg")
}