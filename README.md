# ScopingTools
### AWS Scanner Usage
Using Access Keys\
```python aws_scanner.py --aws_access_key_id [aws_access_key] --aws_secret_access_key [aws_secret_access_key] --region_name [region_name] --output-json [file_name]```

Using Role ARN\
```python aws_scanner.py --role_arn [role_arn] --region_name [region_name] --output-csv [file_name]```

Using AWS SSO\
```python aws_scanner.py --sso --region_name [region_name] --output-xml [file_name]```\
```python aws_scanner.py --sso_profile [profile_name] --region_name [region_name] --output-xml [file_name]```

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

### To setup AWS SSO
1. Make an account using IAM Identity Center, add a user and take note of the credentials.
2. Make a permission set.
3. Run ```aws configure sso``` on your cli and put in your credentials.

### Scans the following
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
