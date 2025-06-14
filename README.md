# ScopingTools
### AWS Scanner Usage
Using Access Keys\
```python aws_scanner.py --aws_access_key_id [aws_access_key] --aws_secret_access_key [aws_secret_access_key] --region_name [region_name] --output-json [file_name]```

Using Role ARN\
```python aws_scanner.py --role_arn [role_arn] --region_name [region_name] --output-csv [file_name]```

Using AWS SSO\
```python aws_scanner.py --sso --region_name [region_name] --output-xml [file_name]```\
```python aws_scanner.py --sso_profile [profile_name] --region_name [region_name] --output-xml [file_name]```

### To setup Access Keys
1. Sign in to your AWS Account
2. Click on your profile on the top left corner and select Security Credentials
3. Find the Access Key section and click Create access key
4. Follow the intructions

### To setup Role ARN
1. Create a new role on AWS
2. Choose an AWS account
3. Attach necessary permissions (Recommended to use Read-Only permissions)
4. After creating role, edit your role and go to Trust Policies
5. Edit trust policy and replace with
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT-ID-WITHOUT-HYPHENS:user/YourIAMUser"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```
Make sure to replace ```ACCOUNT-ID-WITHOUT-HYPENS``` with your AccountID and make sure to replace ```YourIAMUser``` with your IAM user\
6. Copy the Role ARN\
7. Go to your selected user and edit permissions\
8. Create an inline policy with this:\
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/MyRole"
    }
  ]
}
```
Make sure to replace ```arn:aws:iam::123456789012:role/MyRole``` with your actual Role ARN

#### To setup AWS SSO
1. Make an account using IAM Identity Center, add a user and take note of the credentials
2. Make a permission set
3. Run ```aws configure sso``` on your cli and put in your credentials

#### Scans the following
EC2\
ECS\
ELBv2\
RDS\
CloudFront\
S3\
API Gateway\
Lightsail\
Elastic Beanstalk\
Route 53\
EKS\
App Runner\
Amplify\
IoT\
Global Accelerator\
MQ\
GameLift\
Managed Blockchain

### GCP Scanner Usage
Using Access Keys\
```python gcp_scanner.py --service_account_key [/path/to/key.json] --project_id [project-id]```

Using OAuth Token\
```python scanner.py --oauth_token [access_token] --project_id [project-id]```

### To setup Access Keys\
1. Login to your GCP account
2. Navigate to IAM & Admin > Service Account
3. Create service account and follow the instructions
4. Click on the created service account and navigate to the "Keys" tab
5. Add key using the JSON format

### To setup OAuth Token
0. Install Google Cloud SDK if not already installed
1. Go to your terminal
2. Login to using ```gcloud init```
3. Run the command ```gcloud auth application-default login``` to use access tokens
4. Authenticate and Get token using the command ```gcloud auth application-default print-access-token```

#### Scans the following
Compute Instances\
Kubernetes Clusters\
Storage Buckets\
Cloud SQL Instances\
IAM Service Accounts\
Cloud Functions\
Pub/Sub Topics\
Cloud Run Services\
Spanner Instances\
Memorystore Instances\
Filestore Instances\