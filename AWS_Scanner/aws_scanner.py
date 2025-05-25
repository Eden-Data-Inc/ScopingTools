# Copyright 2025 IntegSec LLC

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
# files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, 
# modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software 
# is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,  
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import boto3
import argparse
import csv
import json
import socket
import xml.etree.ElementTree as ET
from tabulate import tabulate
from botocore.exceptions import ClientError, ProfileNotFound

def parse_arguments():
    parser = argparse.ArgumentParser(description="AWS Resource Manager")
    parser.add_argument("--role_arn", help="AWS Role ARN")
    parser.add_argument("--aws_access_key_id", help="AWS Access Key ID")
    parser.add_argument("--aws_secret_access_key", help="AWS Secret Access Key")
    parser.add_argument("--region_name", help="AWS Region (optional; scans all regions if not specified)")
    parser.add_argument("--sso", action="store_true", help="Use AWS SSO for authentication")
    parser.add_argument("--sso_profile", help="AWS SSO Profile Name")
    parser.add_argument("--output-json", help="Output file name for JSON format (without extension)")
    parser.add_argument("--output-csv", help="Output file name for CSV format (without extension)")
    parser.add_argument("--output-xml", help="Output file name for XML format (without extension)")
    parser.add_argument("--comprehensive", action="store_true", help="Scan everything")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
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

def resolve_ip_address(resource):
    try:
        return socket.gethostbyname(resource)
    except socket.gaierror:
        return "N/A"

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

def get_all_regions(args):
    args_copy = vars(args).copy()
    args_copy["region_name"] = "us-east-1"
    ec2 = get_aws_client("ec2", argparse.Namespace(**args_copy))
    regions = ec2.describe_regions()['Regions']
    return [region['RegionName'] for region in regions]

def list_s3_hosted_cloudfront_distributions(cloudfront_client):
    s3_backed_distributions = []
    paginator = cloudfront_client.get_paginator("list_distributions")
    for page in paginator.paginate():
        for dist in page.get("DistributionList", {}).get("Items", []):
            for origin in dist["Origins"]["Items"]:
                domain_name = origin.get("DomainName", "")
                if domain_name.endswith(".s3.amazonaws.com"):
                    dist_id = dist.get("Id", "N/A")
                    dist_domain = dist.get("DomainName", "N/A")
                    s3_backed_distributions.append(f"{dist_domain}:443")
    return s3_backed_distributions

def list_ec2_public_ips(ec2_client):
    response = ec2_client.describe_instances()
    external_hosts = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            if 'PublicIpAddress' in instance:
                public_ip = instance['PublicIpAddress']
                public_dns = instance.get('PublicDnsName', 'N/A')
                external_hosts.append(f"{public_ip}")
                if public_dns != 'N/A':
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

def list_waf_web_acl(waf_client):
    response = waf_client.list_web_acls(Scope='REGIONAL')
    waf_resources = []
    for acl in response.get('WebACLs', []):
        waf_resources.append(f"{acl.get('Name', 'N/A')}:{acl.get('ARN', 'N/A')}")
    return waf_resources

def list_nat_gateways(ec2_client):
    response = ec2_client.describe_nat_gateways()
    nat_resources = []
    for nat in response.get('NatGateways', []):
        for address in nat.get('NatGatewayAddresses', []):
            ip = address.get('PublicIp')
            if ip:
                nat_resources.append(f"{ip}:443")
    return nat_resources

def list_rds_instances(rds_client):
    response = rds_client.describe_db_instances()
    rds_resources = []
    for db in response.get('DBInstances', []):
        if db.get('PubliclyAccessible', False):
            endpoint = db.get('Endpoint', {}).get('Address')
            port = db.get('Endpoint', {}).get('Port', 3306)
            if endpoint:
                rds_resources.append(f"{endpoint}:{port}")
    return rds_resources

def list_cloudfront_distributions(cloudfront_client):
    response = cloudfront_client.list_distributions()
    cloudfront_resources = []
    dist_list = response.get('DistributionList', {}).get('Items', [])
    for dist in dist_list:
        domain_name = dist.get('DomainName')
        if domain_name:
            cloudfront_resources.append(f"{domain_name}:443")
    return cloudfront_resources

def list_aurora_clusters(rds_client):
    response = rds_client.describe_db_clusters()
    aurora_resources = []
    for cluster in response.get('DBClusters', []):
        if cluster.get('Endpoint'):
            endpoint = cluster['Endpoint']
            port = cluster.get('Port', 3306)
            aurora_resources.append(f"{endpoint}:{port}")
    return aurora_resources

def list_aurora_clusters(rds_client):
    response = rds_client.describe_db_clusters()
    aurora_resources = []
    for cluster in response.get('DBClusters', []):

        endpoint = cluster.get('Endpoint')
        if endpoint:
            port = cluster.get('Port', 3306)
            aurora_resources.append(f"{endpoint}:{port}")
    return aurora_resources

def list_appsync_apis(appsync_client):
    response = appsync_client.list_graphql_apis()
    appsync_endpoints = []
    for api in response.get('graphqlApis', []):
        endpoint = api.get('uris', {}).get('GRAPHQL')
        if endpoint:
            appsync_endpoints.append(f"{endpoint}:443")
    return appsync_endpoints

def list_lambda_urls(lambda_client):
    response = lambda_client.list_functions()
    lambda_urls = []
    for function in response.get('Functions', []):
        try:
            url_config = lambda_client.get_function_url_config(FunctionName=function['FunctionName'])
            function_url = url_config.get('FunctionUrl')
            if function_url:
                lambda_urls.append(f"{function_url.replace('https://', '').rstrip('/')}:443")
        except lambda_client.exceptions.ResourceNotFoundException:
            continue  # Skip if no URL config
    return lambda_urls

def list_fargate_tasks_public_ips(ecs_client):
    fargate_public_ips = []
    clusters = ecs_client.list_clusters().get('clusterArns', [])
    for cluster in clusters:
        services = ecs_client.list_services(cluster=cluster).get('serviceArns', [])
        for service in services:
            service_details = ecs_client.describe_services(cluster=cluster, services=[service])['services']
            for s in service_details:
                if s.get('launchType') == 'FARGATE':
                    task_arns = ecs_client.list_tasks(cluster=cluster, serviceName=s['serviceName']).get('taskArns', [])
                    if task_arns:
                        tasks = ecs_client.describe_tasks(cluster=cluster, tasks=task_arns).get('tasks', [])
                        for task in tasks:
                            attachments = task.get('attachments', [])
                            for attachment in attachments:
                                if attachment['type'] == 'ElasticNetworkInterface':
                                    for detail in attachment['details']:
                                        if detail['name'] == 'publicIpv4Address':
                                            fargate_public_ips.append(f"{detail['value']}:80")
                                            fargate_public_ips.append(f"{detail['value']}:443")
    return fargate_public_ips

def list_opensearch_domains(opensearch_client):
    response = opensearch_client.list_domain_names()
    domains = []
    for domain_info in response.get('DomainNames', []):
        domain_name = domain_info['DomainName']
        domain_detail = opensearch_client.describe_domain(DomainName=domain_name)
        endpoint = domain_detail['DomainStatus'].get('Endpoint')
        if endpoint:
            domains.append(f"{endpoint}:443")
    return domains

def list_fsx_filesystems(fsx_client):
    response = fsx_client.describe_file_systems()
    fsx_dns = []
    for fs in response.get('FileSystems', []):
        dns_name = fs.get('DNSName')
        if dns_name:
            fsx_dns.append(f"{dns_name}:445")
    return fsx_dns


def list_transit_gateways(ec2_client):
    response = ec2_client.describe_transit_gateways()
    tgw_ids = []
    for tgw in response.get('TransitGateways', []):
        tgw_ids.append(f"{tgw['TransitGatewayId']}:N/A")
    return tgw_ids

def export_to_json(data, filename="output.json"):
    output = []
    for region, services in data.items():
        for service, resources in services.items():
            for res in resources:
                for item in (res if isinstance(res, list) else [res]):
                    if ":" in item:
                        resource_ip, port = item.rsplit(":", 1)
                    else:
                        resource_ip, port = item, ""
                    output.append({
                        "region": region,
                        "service": service,
                        "resource_ip": resource_ip,
                        "port": port
                    })
    with open(filename + ".json", "w") as json_file:
        json.dump(output, json_file, indent=2)
    print(f"Data exported to {filename}.json")


def export_to_csv(data, filename="output.csv"):
    with open(filename + ".csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Region", "Service", "Resource IP", "Port"])
        for region, services in data.items():
            for service, resources in services.items():
                for res in resources:
                    for item in (res if isinstance(res, list) else [res]):
                        if ":" in item:
                            resource_ip, port = item.rsplit(":", 1)
                        else:
                            resource_ip, port = item, ""
                        writer.writerow([region, service, resource_ip, port])
    print(f"Data exported to {filename}.csv")


def export_to_xml(data, filename="output.xml"):
    root = ET.Element("AWSResources")
    for region, services in data.items():
        for service, resources in services.items():
            for res in resources:
                for item in (res if isinstance(res, list) else [res]):
                    if ":" in item:
                        resource_ip, port = item.rsplit(":", 1)
                    else:
                        resource_ip, port = item, ""
                    res_element = ET.SubElement(root, "Resource")
                    ET.SubElement(res_element, "Region").text = region
                    ET.SubElement(res_element, "Service").text = service
                    ET.SubElement(res_element, "ResourceIP").text = resource_ip
                    ET.SubElement(res_element, "Port").text = port
    tree = ET.ElementTree(root)
    tree.write(filename + ".xml")
    print(f"Data exported to {filename}.xml")



def main():
    args = parse_arguments()
    regions = [args.region_name] if args.region_name else get_all_regions(args)
    all_results = {}

    for region in regions:
        print(f"\nScanning region: {region}")
        args_dict = vars(args).copy()
        args_dict["region_name"] = region
        args_with_region = argparse.Namespace(**args_dict)

        if args.comprehensive:
            aws_services = {
                "ec2": ["list_ec2_public_ips", "list_elastic_ips", "list_transit_gateways", "list_nat_gateways"],
                "ecs": ["list_ecs_services_with_public_lb", "list_fargate_tasks_public_ips"],
                "elbv2": ["list_load_balancers"],
                "s3": ["list_s3_buckets"],
                "apigateway": ["list_api_gateway_endpoints"],
                "lightsail": ["list_lightsail_instances"],
                "elasticbeanstalk": ["list_elastic_beanstalk_environments"],
                "route53": ["list_route53_hosted_zones"],
                "eks": ["list_eks_clusters"],
                "apprunner": ["list_app_runner_services"],
                "amplify": ["list_amplify_apps"],
                "wafv2": ["list_waf_web_acl"],
                "rds": ["list_rds_instances", "list_aurora_clusters"],
                "cloudfront": ["list_cloudfront_distributions", "list_s3_hosted_cloudfront_distributions"],
                "appsync": ["list_appsync_apis"],
                "lambda": ["list_lambda_urls"],
                "opensearch": ["list_opensearch_domains"],
                "fsx": ["list_fsx_filesystems"],
            }
        else:
            aws_services = {
                "ec2": ["list_ec2_public_ips", "list_elastic_ips", "list_transit_gateways", "list_nat_gateways"],
                "wafv2": ["list_waf_web_acl"],
                "rds": ["list_rds_instances", "list_aurora_clusters"],
                "cloudfront": ["list_cloudfront_distributions", "list_s3_hosted_cloudfront_distributions"],
                "apigateway": ["list_api_gateway_endpoints"],
                "appsync": ["list_appsync_apis"],
                "lambda": ["list_lambda_urls"],
                "lightsail": ["list_lightsail_instances"],
                "elasticbeanstalk": ["list_elastic_beanstalk_environments"],
                "ecs": ["list_ecs_services_with_public_lb", "list_fargate_tasks_public_ips"],
                "opensearch": ["list_opensearch_domains"],
                "fsx": ["list_fsx_filesystems"],
            }

        clients = {}
        for service in aws_services:
            try:
                clients[service] = get_aws_client(service, args_with_region)
            except ClientError as e:
                if args.debug:
                    print(f"Error creating client for {service} in region {region}: {e}")
                continue

        results = {}
        table_rows = []

        for service, functions in aws_services.items():
            if service in clients:
                results[service] = []
                for func in functions:
                    try:
                        output = globals()[func](clients[service])
                        results[service].append(output)
                        for item in output:
                            if ':' in item:
                                resource_part, port = item.rsplit(":", 1)
                            else:
                                resource_part, port = item, ''

                            try:
                                socket.inet_aton(resource_part)
                                resource = ''
                                ip_address = resource_part
                            except socket.error:
                                resource = resource_part
                                ip_address = resolve_ip_address(resource_part)

                            table_rows.append([region, service, resource, ip_address, port])
                    except Exception as e:
                        if args.debug:
                            print(f"Error calling {func} for {service} in {region}: {e}")

        all_results[region] = results

        if table_rows:
            ip_to_row = {}
            for row in table_rows:
                ip = row[3]
                current_score = sum(bool(cell.strip()) for cell in row)

                if ip not in ip_to_row:
                    ip_to_row[ip] = (current_score, row)
                else:
                    existing_score = ip_to_row[ip][0]
                    if current_score > existing_score:
                        ip_to_row[ip] = (current_score, row)

            # Extract just the rows
            unique_rows = [entry[1] for entry in ip_to_row.values()]

            # Display the data in a table
            print(tabulate(unique_rows, headers=["Region", "Service", "Resource", "IP Address", "Port"], tablefmt="grid"))
        else:
            print(f"No public-facing resources found in region {region}")

    if args.output_json:
        export_to_json(all_results, args.output_json)
    if args.output_csv:
        export_to_csv(all_results, args.output_csv)
    if args.output_xml:
        export_to_xml(all_results, args.output_xml)

if __name__ == "__main__":
    main()
