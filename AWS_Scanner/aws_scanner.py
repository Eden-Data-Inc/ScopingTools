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
    external_hosts = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if 'PublicIpAddress' in instance:
                public_ip = instance['PublicIpAddress']
                public_dns = instance.get('PublicDnsName', 'N/A')
                ports = [sg['FromPort'] for sg in instance.get('SecurityGroups', []) if 'FromPort' in sg]  # Approximation
                if len(ports) != 0:
                    for port in ports:
                        external_hosts.append(f"{public_ip}:{port}")
                else:
                    external_hosts.append(f"{public_ip}")
                external_hosts.append(f"{public_dns}")
    return external_hosts

def list_elastic_ips(ec2_client):
    response = ec2_client.describe_addresses()
    return [f"{address['PublicIp']}" for address in response['Addresses']]

def list_ecs_services_with_public_lb(ecs_client):
    ecs_services = []
    for cluster_arn in ecs_client.list_clusters()['clusterArns']:
        services_response = ecs_client.list_services(cluster=cluster_arn)
        for service_arn in services_response['serviceArns']:
            service_details = ecs_client.describe_services(cluster=cluster_arn, services=[service_arn])['services']
            for service in service_details:
                for lb in service.get('loadBalancers', []):
                    lb_name = lb.get('loadBalancerName', '')
                    if lb_name:
                        lb_response = ecs_client.describe_load_balancers(Names=[lb_name])
                        for lb_data in lb_response['LoadBalancers']:
                            if lb_data['Scheme'] == 'internet-facing':
                                listeners = ecs_client.describe_listeners(LoadBalancerArn=lb_data['LoadBalancerArn'])
                                ports = [listener['Port'] for listener in listeners['Listeners']]
                                if len(ports) != 0:
                                    for port in ports:
                                        ecs_services.append(f"{lb_data['DNSName']}:{port}")
                                else:
                                    ecs_services.append(f"{lb_data['DNSName']}")
    return ecs_services

def list_load_balancers(elbv2_client):
    response = elbv2_client.describe_load_balancers()
    return [f"{lb['DNSName']}" for lb in response['LoadBalancers'] if lb['Scheme'] == 'internet-facing']

def list_s3_buckets(s3_client):
    response = s3_client.list_buckets()
    return [f"{bucket['Name']}.s3.amazonaws.com:443" for bucket in response['Buckets']]

def list_api_gateway_endpoints(apigateway_client):
    response = apigateway_client.get_rest_apis()
    return [f"{api['id']}.execute-api.amazonaws.com:443" for api in response['items']]

def list_lightsail_instances(lightsail_client):
    response = lightsail_client.get_instances()
    return [f"{instance['publicIpAddress']}" for instance in response['instances'] if 'publicIpAddress' in instance]

def list_elastic_beanstalk_environments(elasticbeanstalk_client):  
   response = elasticbeanstalk_client.describe_environments()  
   environments = []  
   for env in response['Environments']:  
       cname = env.get('CNAME', 'N/A')  
       environments.append(f"{cname}:80")  
       environments.append(f"{cname}:443")  
   return environments

def list_route53_hosted_zones(route53_client):
    response = route53_client.list_hosted_zones()
    return [f"{zone['Name']}" for zone in response['HostedZones']]

def list_eks_clusters(eks_client):
    return [f"{cluster}.eks.amazonaws.com:443" for cluster in eks_client.list_clusters()['clusters']]

def list_app_runner_services(apprunner_client):
   response = apprunner_client.list_services()
   return [f"{service.get('ServiceUrl', 'N/A')}:80" for service in response['ServiceSummaryList']] + \
          [f"{service.get('ServiceUrl', 'N/A')}:443" for service in response['ServiceSummaryList']]

def list_amplify_apps(amplify_client):
   response = amplify_client.list_apps()
   return [f"{app.get('DefaultDomain', 'N/A')}:80" for app in response['apps']] + \
          [f"{app.get('DefaultDomain', 'N/A')}:443" for app in response['apps']]

def list_iot_endpoints(iot_client):
   return [f"{iot_client.describe_endpoint()['endpointAddress']}:8883"] + \
          [f"{iot_client.describe_endpoint()['endpointAddress']}:443"]


def export_to_json(data, filename="output.json"):
    output = []
    for service, resources in data.items():
        for resource in resources:
            if len(resource) != 0:
                output.extend(resource)
    output = [item for item in output]
    with open(filename + ".json", "w") as json_file:
        json_file.write("{" + ", ".join(output) + "}")
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
    output_list = []
    for service, resources in data.items():
        for resource in resources:
            if len(resource) != 0:
                output_list.extend(resource)

    print(output_list)
    output = ', '.join(output_list)
    root.text = str(output)
    tree = ET.ElementTree(root)
    tree.write(filename + ".xml")
    print(f"Data exported to {filename} in XML format.")

def main():
    args = parse_arguments()

    aws_services = {
		"ec2": [
            "list_ec2_public_ips", 
            "list_elastic_ips",
            ],
		"ecs": ["list_ecs_services_with_public_lb"],
		"elbv2": ["list_load_balancers"],
		"s3": ["list_s3_buckets"],
		"apigateway": ["list_api_gateway_endpoints"],
		"lightsail": ["list_lightsail_instances"],
		"elasticbeanstalk": ["list_elastic_beanstalk_environments"],
		"route53": ["list_route53_hosted_zones"],
		"eks": ["list_eks_clusters"],
        "apprunner": ["list_app_runner_services"],
		"amplify": ["list_amplify_apps"],
		"iot": ["list_iot_endpoints"],
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

