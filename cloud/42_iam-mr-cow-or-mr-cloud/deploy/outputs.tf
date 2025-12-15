output "secret_bucket" { value = aws_s3_bucket.secret.bucket }
output "icon_url" { value = "https://${aws_s3_bucket.secret.bucket}.s3.${var.aws_region}.amazonaws.com/assets/cowcloud.svg" }