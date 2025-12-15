#!/usr/bin/env bash
set -euo pipefail

: "${AWS_REGION:?missing}"
: "${CLUSTER_NAME:?missing}"
: "${KUBECONFIG:?missing}"

# Use the current folder as the challenge root
CHALL_ROOT="$(pwd)"
DEPLOY_DIR="${CHALL_ROOT}/deploy"
PUBLIC_DIR="${CHALL_ROOT}/public"

echo "==> Ensuring OIDC provider is associated"
eksctl utils associate-iam-oidc-provider --cluster "${CLUSTER_NAME}" --region "${AWS_REGION}" --approve

echo "==> Fetching cluster endpoint and CA"
CLUSTER_ENDPOINT="$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" --query 'cluster.endpoint' --output text)"
CLUSTER_CA_BASE64="$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" --query 'cluster.certificateAuthority.data' --output text)"

echo "==> Computing OIDC provider ARN"
ISSUER="$(aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" --query 'cluster.identity.oidc.issuer' --output text)"
ACCOUNT_ID="$(aws sts get-caller-identity --query 'Account' --output text)"
OIDC_HOST="${ISSUER#https://}"
EKS_OIDC_PROVIDER_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${OIDC_HOST}"

echo "==> Generating unique S3 bucket name"
STAMP="$(date +%s)"
RAND="$(openssl rand -hex 3)"
S3_BUCKET_NAME="ds-k8s-infinity-flag-${STAMP}-${RAND}"

echo "==> Reading flag value"
FLAG_VALUE="$(tr -d '\n' < "${CHALL_ROOT}/flag.txt")"

echo "==> Writing terraform.tfvars"
cat > "${DEPLOY_DIR}/terraform.tfvars" <<TFVARS
kubeconfig_path        = "${KUBECONFIG}"
aws_region             = "${AWS_REGION}"
eks_oidc_provider_arn  = "${EKS_OIDC_PROVIDER_ARN}"
s3_bucket_name         = "${S3_BUCKET_NAME}"
flag_value             = "${FLAG_VALUE}"
cluster_server         = "${CLUSTER_ENDPOINT}"
cluster_ca_base64      = "${CLUSTER_CA_BASE64}"
TFVARS

echo "==> Terraform init/apply"
pushd "${DEPLOY_DIR}" >/dev/null
terraform init -input=false
terraform apply -auto-approve
popd >/dev/null

echo "==> Rendering player kubeconfig"
mkdir -p "${PUBLIC_DIR}"
kubectl -n infinity-castle get secret player-token -o jsonpath='{.data.token}' | base64 -d > "${PUBLIC_DIR}/player.token"

PLAYER_TOKEN="$(cat "${PUBLIC_DIR}/player.token")"
sed \
  -e "s|BASE64_CLUSTER_CA_PLACEHOLDER|${CLUSTER_CA_BASE64}|g" \
  -e "s|https://YOUR-CLUSTER-ENDPOINT|${CLUSTER_ENDPOINT}|g" \
  -e "s|PLAYER_TOKEN_PLACEHOLDER|${PLAYER_TOKEN}|g" \
  "${PUBLIC_DIR}/kubeconfig.template.yaml" > "${PUBLIC_DIR}/kubeconfig.yaml"

echo "==> Smoke test: kubectl access"
KUBECONFIG="${PUBLIC_DIR}/kubeconfig.yaml" kubectl -n infinity-castle get sa nakime >/dev/null

echo "==> Smoke test: assume role and read flag"
KUBECONFIG="${PUBLIC_DIR}/kubeconfig.yaml" kubectl -n infinity-castle get sa nakime -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}' > "${PUBLIC_DIR}/role.arn"
KUBECONFIG="${PUBLIC_DIR}/kubeconfig.yaml" kubectl -n infinity-castle get secret nakime-token -o json | jq -r '.data.token' | base64 -d > "${PUBLIC_DIR}/nakime.jwt"

aws sts assume-role-with-web-identity \
  --role-arn "$(cat "${PUBLIC_DIR}/role.arn")" \
  --role-session-name infinity-session \
  --web-identity-token "file://${PUBLIC_DIR}/nakime.jwt" \
  --duration-seconds 900 > "${PUBLIC_DIR}/creds.json"

export AWS_ACCESS_KEY_ID="$(jq -r .Credentials.AccessKeyId "${PUBLIC_DIR}/creds.json")"
export AWS_SECRET_ACCESS_KEY="$(jq -r .Credentials.SecretAccessKey "${PUBLIC_DIR}/creds.json")"
export AWS_SESSION_TOKEN="$(jq -r .Credentials.SessionToken "${PUBLIC_DIR}/creds.json")"

BUCKET_NAME="$(KUBECONFIG="${PUBLIC_DIR}/kubeconfig.yaml" kubectl -n infinity-castle get cm ds-k8s-display -o jsonpath='{.data.bucket}')"
aws s3 cp "s3://${BUCKET_NAME}/flag.txt" - >/dev/null

echo "==> Packaging player kit"
pushd "${PUBLIC_DIR}" >/dev/null
zip -q -r ../infinity-token-player-kit.zip kubeconfig.yaml INSTRUCTIONS.md
popd >/dev/null

echo "==> Done."
echo "Distribute: ${CHALL_ROOT}/infinity-token-player-kit.zip"
echo "Players run with: export KUBECONFIG=kubeconfig.yaml"