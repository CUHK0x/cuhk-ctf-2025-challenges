output "namespace" {
  value = "infinity-castle"
}

output "nakime_role_arn" {
  value = aws_iam_role.irsa.arn
}

output "s3_flag_bucket" {
  value = aws_s3_bucket.flag.bucket
}

output "s3_flag_key" {
  value = aws_s3_object.flag_obj.key
}

output "cluster_ca_base64_out" {
  value = var.cluster_ca_base64
}

output "cluster_server_out" {
  value = var.cluster_server
}