import boto3
import argparse
import csv
import json
import xml.etree.ElementTree as ET
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

def parse_arguments():
    parser = argparse.ArgumentParser(description="AWS Resource Manager")
    parser.add_argument("--role_arn", help="AWS Role ARN")
    parser.add_argument("--aws_access_key_id", help="AWS Access Key ID")
    parser.add_argument("--aws_secret_access_key", help="AWS Secret Access Key")
    parser.add_argument("--region_name", required=True, help="AWS Region (default: us-east-2)")
    parser.add_argument("--sso", action="store_true", help="Use AWS SSO for authentication")
    parser.add_argument("--sso_profile", help="AWS SSO Profile Name")
    parser.add_argument("--output-json", help="Output file name for JSON format (without extension)")
    parser.add_argument("--output-csv", help="Output file name for CSV format (without extension)")
    parser.add_argument("--output-xml", help="Output file name for XML format (without extension)")
    return parser.parse_args()

def assume_role(role_arn):
    sts_client = boto3.client("sts")
    response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="Session")
    credentials = response["Credentials"]
    return {
        "aws_access_key_id": credentials["AccessKeyId"],
        "aws_secret_access_key": credentials["SecretAccessKey"],
        "aws_session_token": credentials["SessionToken"],
    }

def get_aws_client(service_name, args):
    if args.role_arn:
        creds = assume_role(args.role_arn)
        return boto3.client(
            service_name,
            aws_access_key_id=creds["aws_access_key_id"],
            aws_secret_access_key=creds["aws_secret_access_key"],
            aws_session_token=creds["aws_session_token"],
            region_name=args.region_name,
        )
    elif args.aws_access_key_id and args.aws_secret_access_key:
        return boto3.client(
            service_name,
            aws_access_key_id=args.aws_access_key_id,
            aws_secret_access_key=args.aws_secret_access_key,
            region_name=args.region_name,
        )
    elif args.sso:
        try:
            session = boto3.Session(profile_name=args.sso_profile) if args.sso_profile else boto3.Session()
            return session.client(service_name, region_name=args.region_name)
        except ProfileNotFound:
            print("SSO profile not found. Ensure you have run 'aws configure sso' and provided a valid profile.")
            exit(1)
    else:
        print("Please choose a valid authentication method: --role_arn, --aws_access_key_id & --aws_secret_access_key, or --sso.")
        exit(1)

def list_ec2_public_ips(ec2_client):
    response = ec2_client.describe_instances()
    public_ips = [
        instance['PublicIpAddress']
        for reservation in response['Reservations']
        for instance in reservation['Instances']
        if 'PublicIpAddress' in instance
    ]
    return public_ips

def list_elastic_ips(ec2_client):
    response = ec2_client.describe_addresses()
    return [address['PublicIp'] for address in response['Addresses']]

def list_ecs_services_with_public_lb(ecs_client):
    ecs_services = []
    for cluster_arn in ecs_client.list_clusters()['clusterArns']:
        services_response = ecs_client.list_services(cluster=cluster_arn)
        for service_arn in services_response['serviceArns']:
            service_details = ecs_client.describe_services(cluster=cluster_arn, services=[service_arn])['services']
            for service in service_details:
                if any('Public' in lb.get('loadBalancerName', '') for lb in service.get('loadBalancers', [])):
                    ecs_services.append(service)
    return ecs_services

def list_load_balancers(elbv2_client):
    response = elbv2_client.describe_load_balancers()
    return [lb['LoadBalancerName'] for lb in response['LoadBalancers'] if lb['Scheme'] == 'internet-facing']

def list_public_rds_instances(rds_client):
    response = rds_client.describe_db_instances()
    return [db['DBInstanceIdentifier'] for db in response['DBInstances'] if db.get('PubliclyAccessible')]

def list_cloudfront_distributions(cloudfront_client):
    try:
        response = cloudfront_client.list_distributions()
        return [
            dist['Id']
            for dist in response.get('DistributionList', {}).get('Items', [])
        ]
    except ClientError as e:
        print(f"Error listing CloudFront distributions: {e}")
        return []

def list_s3_buckets(s3_client):
    response = s3_client.list_buckets()
    return [bucket['Name'] for bucket in response['Buckets']]

def list_api_gateway_endpoints(apigateway_client):
    response = apigateway_client.get_rest_apis()
    return [api['id'] for api in response['items']]

def list_lightsail_instances(lightsail_client):
    response = lightsail_client.get_instances()
    return [
        {'InstanceName': instance['name'], 'PublicIp': instance['publicIpAddress']}
        for instance in response['instances']
        if 'publicIpAddress' in instance
    ]

def list_elastic_beanstalk_environments(elasticbeanstalk_client):
    response = elasticbeanstalk_client.describe_environments()
    return [env['EnvironmentName'] for env in response['Environments']]

def list_route53_hosted_zones(route53_client):
    response = route53_client.list_hosted_zones()
    return [zone['Name'] for zone in response['HostedZones']]

def list_eks_clusters(eks_client):
    return eks_client.list_clusters()['clusters']

def list_app_runner_services(apprunner_client):
    response = apprunner_client.list_services()
    return [service['ServiceName'] for service in response['ServiceSummaryList']]

def list_amplify_apps(amplify_client):
    response = amplify_client.list_apps()
    return [app['appName'] for app in response['apps']]

def list_iot_endpoints(iot_client):
    return [iot_client.describe_endpoint()['endpointAddress']]

def list_global_accelerator_configurations(globalaccelerator_client):
    try:
        response = globalaccelerator_client.list_accelerators()
        return [acc['Name'] for acc in response['Accelerators']]
    except:
        return []

def list_mq_brokers(mq_client):
    response = mq_client.list_brokers()
    return [broker['BrokerName'] for broker in response['BrokerSummaries']]


def list_lambda_functions(lambda_client):
    response = lambda_client.list_functions()
    return [func['FunctionName'] for func in response['Functions']]

def list_batch_compute_environments(batch_client):
    response = batch_client.describe_compute_environments()
    return [env['computeEnvironmentName'] for env in response['computeEnvironments']]

def list_vpcs(ec2_client):
    response = ec2_client.describe_vpcs()
    return [vpc['VpcId'] for vpc in response['Vpcs']]

def list_subnets(ec2_client):
    response = ec2_client.describe_subnets()
    return [subnet['SubnetId'] for subnet in response['Subnets']]

def list_route_tables(ec2_client):
    response = ec2_client.describe_route_tables()
    return [rt['RouteTableId'] for rt in response['RouteTables']]

def list_dynamodb_tables(dynamodb_client):
    response = dynamodb_client.list_tables()
    return response['TableNames']

def list_redshift_clusters(redshift_client):
    response = redshift_client.describe_clusters()
    return [cluster['ClusterIdentifier'] for cluster in response['Clusters']]

def list_iam_users(iam_client):
    response = iam_client.list_users()
    return [user['UserName'] for user in response['Users']]

def list_iam_roles(iam_client):
    response = iam_client.list_roles()
    return [role['RoleName'] for role in response['Roles']]

def list_secrets(secrets_manager_client):
    response = secrets_manager_client.list_secrets()
    return [secret['Name'] for secret in response['SecretList']]

def list_cloudwatch_alarms(cloudwatch_client):
    response = cloudwatch_client.describe_alarms()
    return [alarm['AlarmName'] for alarm in response['MetricAlarms']]

def list_ssm_managed_instances(ssm_client):
    response = ssm_client.describe_instance_information()
    return [instance['InstanceId'] for instance in response['InstanceInformationList']]

def list_codebuild_projects(codebuild_client):
    response = codebuild_client.list_projects()
    return response['projects']

def list_codepipeline_pipelines(codepipeline_client):
    response = codepipeline_client.list_pipelines()
    return [pipeline['name'] for pipeline in response['pipelines']]

def list_sagemaker_endpoints(sagemaker_client):
    response = sagemaker_client.list_endpoints()
    return [endpoint['EndpointName'] for endpoint in response['Endpoints']]

def list_rekognition_collections(rekognition_client):
    response = rekognition_client.list_collections()
    return response['CollectionIds']

def list_emr_clusters(emr_client):
    response = emr_client.list_clusters()
    return [cluster['Id'] for cluster in response['Clusters']]

def list_appsync_apis(appsync_client):
    response = appsync_client.list_graphql_apis()
    return [api['name'] for api in response['graphqlApis']]

def list_gamelift_fleets(gamelift_client):
    response = gamelift_client.list_fleets()
    return response.get('FleetIds', [])

def list_blockchain_networks(blockchain_client):
    try:
        response = blockchain_client.list_networks()
        return [network['Name'] for network in response['Networks']]
    except:
        return ''

def export_to_json(data, filename="output.json"):
    output = []
    for service, resources in data.items():
        for resource in resources:
            if len(resource) != 0:
                output.extend(resource)
    with open(filename + ".json", "w") as json_file:
            json.dump(output, json_file, indent=None)
    print(f"Data exported to {filename} in JSON format.")

def export_to_csv(data, filename="output.csv"):
    output = []
    with open(filename + ".csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        for service, resources in data.items():
            #writer.writerow([service])
            for resource in resources:
                if len(resource) != 0:
                    output.extend(resource)
        writer.writerows([output])
    print(f"Data exported to {filename} in CSV format.")

def export_to_xml(data, filename="output.xml"):
    root = ET.Element("AWSResources")
    for service, resources in data.items():
        for resource in resources:
            if len(resource) != 0:
                output = ', '.join(resource)
                service_element = ET.SubElement(root, service)
                service_element.text = str(output)
    tree = ET.ElementTree(root)
    tree.write(filename + ".xml")
    print(f"Data exported to {filename} in XML format.")


def main():
    args = parse_arguments()

    aws_services = {
		"ec2": [
            "list_ec2_public_ips", 
            "list_elastic_ips",
            "list_vpcs",
            "list_subnets",
            "list_route_tables",
            ],
		"ecs": ["list_ecs_services_with_public_lb"],
		"elbv2": ["list_load_balancers"],
		"rds": ["list_public_rds_instances"],
		"cloudfront": ["list_cloudfront_distributions"],
		"s3": ["list_s3_buckets"],
		"apigateway": ["list_api_gateway_endpoints"],
		"lightsail": ["list_lightsail_instances"],
		"elasticbeanstalk": ["list_elastic_beanstalk_environments"],
		"route53": ["list_route53_hosted_zones"],
		"eks": ["list_eks_clusters"],
        "apprunner": ["list_app_runner_services"],
		"amplify": ["list_amplify_apps"],
		"iot": ["list_iot_endpoints"],
		"globalaccelerator": ["list_global_accelerator_configurations"],
		"mq": ["list_mq_brokers"],
        "lambda": ["list_lambda_functions"],
        "batch": ["list_batch_compute_environments"],
        "dynamodb": ["list_dynamodb_tables"],
        "redshift": ["list_redshift_clusters"],
        "iam": [
            "list_iam_users",
            "list_iam_roles",
        ],
        "secretsmanager": ["list_secrets"],
        "cloudwatch": ["list_cloudwatch_alarms"],
        "ssm": ["list_ssm_managed_instances"],
        "codebuild": ["list_codebuild_projects"],
        "codepipeline": ["list_codepipeline_pipelines"],
        "sagemaker": ["list_sagemaker_endpoints"],
        "rekognition": ["list_rekognition_collections"],
        "emr": ["list_emr_clusters"],
        "appsync": ["list_appsync_apis"],
        "gamelift": ["list_gamelift_fleets"],
        "managedblockchain": ["list_blockchain_networks"],
	}
    clients = {service: get_aws_client(service, args) for service in aws_services}
    results = {service: [globals()[func](clients[service]) for func in functions] for service, functions in aws_services.items()}
    for service, resources in results.items():
        for resource in resources:
            if len(resource) != 0:
                for i in resource:
                    print(i)

    if args.output_json:
        export_to_json(results, args.output_json)
    if args.output_csv:
        export_to_csv(results, args.output_csv)
    if args.output_xml:
        export_to_xml(results, args.output_xml)


if __name__ == "__main__":
    main()

