# Deploy Guide — infinity-token

This deploys an EKS challenge that uses **IRSA** to retrieve a single S3 object as the flag.

---

## Prerequisites

* Terraform **>= 1.6**
* An existing **EKS cluster** with **OIDC provider** enabled
* `kubectl` access to that cluster
* AWS credentials with permission to create **IAM roles** and **S3** resources

> Challenge namespace is fixed: **`infinity-castle`**

---

## Variables

Create `deploy/terraform.tfvars` with exact values for your environment:

```hcl
kubeconfig_path       = "/absolute/path/to/your/kubeconfig"
aws_region            = "us-west-2"
eks_oidc_provider_arn = "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/<OIDC_ID>"
s3_bucket_name        = "ds-k8s-infinity-flag-unique-<suffix>"  # must be globally unique
flag_value            = "cuhk25ctf{n4k1m3_b1w4_01dc_w4rp_g4t3}"
cluster_server        = "https://XXXXXXXX.gr7.us-west-2.eks.amazonaws.com"
cluster_ca_base64     = "BASE64_OF_CLUSTER_CA"
```

### How to find `cluster_server` and `cluster_ca_base64`

```bash
aws eks describe-cluster \
  --name <YOUR_EKS_CLUSTER_NAME> \
  --region <REGION> \
  --query 'cluster.{server:endpoint,ca:certificateAuthority.data}' \
  --output json
```

Copy `server` to `cluster_server` and `ca` to `cluster_ca_base64`.

---

## Apply

From the `deploy/` directory:

```bash
cd deploy
terraform init
terraform apply -auto-approve
```

---

## Prepare the player kubeconfig

> All commands below assume you are still in `deploy/`.

### 1) Retrieve the player token

**Option A — Secret-backed token (classic clusters):**

```bash
kubectl -n infinity-castle get secret player-token -o jsonpath='{.data.token}' | base64 -d > ../public/player.token || true

# If the fixed name doesn't exist, discover it dynamically
kubectl -n infinity-castle get secret \
  -l 'kubernetes.io/service-account.name=player' \
  -o jsonpath='{.items[0].data.token}' | base64 -d > ../public/player.token
```

**Option B — Projection token (K8s ≥ 1.24):**

```bash
kubectl -n infinity-castle create token player > ../public/player.token
```

### 2) Render kubeconfig from template

Export values and substitute placeholders in `../public/kubeconfig.template.yaml`:

```bash
PLAYER_TOKEN="$(cat ../public/player.token)"
BASE64_CA="$(terraform output -raw cluster_ca_base64_out)"
SERVER_ENDPOINT="$(terraform output -raw cluster_server_out)"

sed -e "s|BASE64_CLUSTER_CA_PLACEHOLDER|${BASE64_CA}|g" \
    -e "s|PLAYER_TOKEN_PLACEHOLDER|${PLAYER_TOKEN}|g" \
    -e "s|https://YOUR-CLUSTER-ENDPOINT|${SERVER_ENDPOINT}|g" \
    ../public/kubeconfig.template.yaml > ../public/kubeconfig.yaml
```

Distribute **`../public/kubeconfig.yaml`** and **`../public/INSTRUCTIONS.md`** to players.

---

## Destroy

When finished:

```bash
terraform destroy -auto-approve
```

---

## Notes & Troubleshooting

* **Bucket name must be globally unique.** If apply fails with `BucketAlreadyExists`, change the `<suffix>`.
* **Verify OIDC:**

  ```bash
  aws eks describe-cluster --name <CLUSTER_NAME> --region <REGION> \
    --query 'cluster.identity.oidc.issuer' --output text
  ```
* **Token retrieval differences:** If `player-token` Secret doesn’t exist, use the projection token method.
* **Security:** Treat `../public/player.token` as sensitive; remove it after rendering kubeconfig.
