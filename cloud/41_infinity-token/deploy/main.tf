terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.25.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.40.0"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "aws" {
  region = var.aws_region
}

# --------------------------
# KUBERNETES NAMESPACE & RBAC
# --------------------------

resource "kubernetes_namespace" "ns" {
  metadata {
    name = "infinity-castle"
    labels = {
      theme = "daemon-slayer-k-infinity-s"
    }
  }
}

resource "kubernetes_service_account" "player" {
  metadata {
    name      = "player"
    namespace = kubernetes_namespace.ns.metadata[0].name
  }
  automount_service_account_token = false
}

resource "kubernetes_role" "ro" {
  metadata {
    name      = "ctf-readonly"
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels = { theme = "daemon-slayer-k-infinity-s" }
  }
  rule {
    api_groups = [""]
    resources  = ["pods","configmaps","events","serviceaccounts","nodes"]
    verbs      = ["get","list","watch"]
  }
  rule {
    api_groups = ["apps"]
    resources  = ["deployments","replicasets","statefulsets"]
    verbs      = ["get","list","watch"]
  }
    rule {
    api_groups = [""]
    resources  = ["serviceaccounts/token"]
    verbs      = ["create"]
  }
}

resource "kubernetes_role_binding" "bind_player" {
  metadata {
    name      = "bind-player-ro"
    namespace = kubernetes_namespace.ns.metadata[0].name
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.ro.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.player.metadata[0].name
    namespace = kubernetes_namespace.ns.metadata[0].name
  }
}

resource "kubernetes_secret" "player_token" {
  metadata {
    name      = "player-token"
    namespace = kubernetes_namespace.ns.metadata[0].name
    annotations = {
      "kubernetes.io/service-account.name" = kubernetes_service_account.player.metadata[0].name
    }
  }
  type = "kubernetes.io/service-account-token"
}

# --------------------------
# IRSA SERVICEACCOUNT (nakime)
# --------------------------

data "aws_iam_openid_connect_provider" "oidc" {
  arn = var.eks_oidc_provider_arn
}

resource "kubernetes_service_account" "nakime" {
  metadata {
    name      = "nakime"
    namespace = kubernetes_namespace.ns.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.irsa.arn
    }
    labels = {
      theme = "daemon-slayer-k-infinity-s"
    }
  }
  automount_service_account_token = false
  depends_on = [aws_iam_role.irsa]
}

resource "kubernetes_secret" "nakime_token" {
  metadata {
    name      = "nakime-token"
    namespace = kubernetes_namespace.ns.metadata[0].name
    annotations = {
      "kubernetes.io/service-account.name" = kubernetes_service_account.nakime.metadata[0].name
    }
  }
  type = "kubernetes.io/service-account-token"
}

# Display bucket name for players
resource "kubernetes_config_map" "display" {
  metadata {
    name      = "ds-k8s-display"
    namespace = kubernetes_namespace.ns.metadata[0].name
    labels = {
      theme = "daemon-slayer-k-infinity-s"
    }
  }
  data = {
    bucket = aws_s3_bucket.flag.bucket
  }
}

# --------------------------
# AWS: S3 FLAG BUCKET + OBJECT
# --------------------------

resource "aws_s3_bucket" "flag" {
  bucket = var.s3_bucket_name

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket_public_access_block" "flag_block" {
  bucket                  = aws_s3_bucket.flag.id
  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_s3_bucket_versioning" "flag_ver" {
  bucket = aws_s3_bucket.flag.id
  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_s3_object" "flag_obj" {
  bucket       = aws_s3_bucket.flag.id
  key          = "flag.txt"
  content      = var.flag_value
  content_type = "text/plain"
}

# --------------------------
# AWS: IRSA ROLE + POLICY
# --------------------------

locals {
  oidc_host = trim(data.aws_iam_openid_connect_provider.oidc.url, "https://")
  sa_sub    = "system:serviceaccount:infinity-castle:nakime"
}

resource "aws_iam_role" "irsa" {
  name = "ds-k8s-infinity-irsa-${kubernetes_namespace.ns.metadata[0].name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.oidc.arn
      },
      Action = "sts:AssumeRoleWithWebIdentity",
      Condition = {
        StringEquals = {
          "${local.oidc_host}:aud" = "sts.amazonaws.com",
          "${local.oidc_host}:sub" = local.sa_sub
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "irsa_s3_ro" {
  name = "ds-k8s-infinity-irsa-s3-ro"
  role = aws_iam_role.irsa.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "S3ReadFlagOnly",
        Effect = "Allow",
        Action = ["s3:GetObject"],
        Resource = "${aws_s3_bucket.flag.arn}/flag.txt"
      },
      {
        Sid    = "ListBucketForFlag",
        Effect = "Allow",
        Action = ["s3:ListBucket"],
        Resource = aws_s3_bucket.flag.arn,
        Condition = {
          StringEquals = {
            "s3:prefix" = "flag.txt"
          }
        }
      },
      {
        Sid    = "DenyMutations",
        Effect = "Deny",
        Action = [
          "s3:DeleteObject",
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:DeleteObjectTagging",
          "s3:PutObjectTagging"
        ],
        Resource = "${aws_s3_bucket.flag.arn}/*"
      }
    ]
  })
}