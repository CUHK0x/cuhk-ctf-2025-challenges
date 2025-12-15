variable "kubeconfig_path" {
  type        = string
  description = "Absolute path to a kubeconfig with admin access to the target EKS cluster."
}

variable "aws_region" {
  type        = string
  description = "AWS region for IAM and S3."
}

variable "eks_oidc_provider_arn" {
  type        = string
  description = "ARN of the cluster's EKS OIDC provider."
}

variable "s3_bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name for the flag."
}

variable "flag_value" {
  type        = string
  description = "Exact flag text placed into s3://<bucket>/flag.txt."
}

variable "cluster_server" {
  type        = string
  description = "EKS cluster API server endpoint."
}

variable "cluster_ca_base64" {
  type        = string
  description = "Base64-encoded cluster CA certificate."
}