# Copyright 2025 IntegSec, LLC

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation 
# files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, 
# modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software 
# is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,  
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import argparse
import csv
import json
import xml.etree.ElementTree as ET
from azure.identity import (
    AzureCliCredential,
    ManagedIdentityCredential,
    EnvironmentCredential
)
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.network.models import ApplicationGateway, BastionHost

def parse_arguments():
    parser = argparse.ArgumentParser(description="Azure Resource Manager")
    parser.add_argument("--auth-method", choices=["cli", "managed-identity", "env"], required=True, help="Authentication method")
    parser.add_argument("--subscription-id", required=True, help="Azure Subscription ID")
    parser.add_argument("--tenant-id", required=False, help="Azure Tenant ID (optional, required for tenant-scoped queries)")
    parser.add_argument("--output-json", help="Output file name for JSON format (without extension)")
    parser.add_argument("--output-csv", help="Output file name for CSV format (without extension)")
    parser.add_argument("--output-xml", help="Output file name for XML format (without extension)")
    return parser.parse_args()

def get_azure_credential(auth_method):
    if auth_method == "cli":
        return AzureCliCredential()
    elif auth_method == "managed-identity":
        return ManagedIdentityCredential()
    elif auth_method == "env":
        return EnvironmentCredential()
    else:
        raise ValueError("Invalid authentication method specified")

def list_virtual_machines(compute_client, network_client):
    vms = []
    for vm in compute_client.virtual_machines.list_all():
        vm_name = vm.name
        nic_id = vm.network_profile.network_interfaces[0].id
        nic_name = nic_id.split("/")[-1]
        resource_group = vm.id.split("/")[4]
        nic = network_client.network_interfaces.get(resource_group, nic_name)

        public_ip = "N/A"
        for ip_config in nic.ip_configurations:
            if ip_config.public_ip_address:
                public_ip_id = ip_config.public_ip_address.id
                public_ip_name = public_ip_id.split("/")[-1]
                public_ip = network_client.public_ip_addresses.get(resource_group, public_ip_name).ip_address

        vms.append(f"{public_ip}")
    return vms

def list_storage_accounts(storage_client):
    return [account.name for account in storage_client.storage_accounts.list()]

def list_sql_servers(sql_client):
    return [server.name for server in sql_client.servers.list()]

def list_kubernetes_clusters(container_client, network_client):
    clusters = []
    for cluster in container_client.managed_clusters.list():
        cluster_name = cluster.name
        node_pool_ips = [np.ip for np in cluster.agent_pool_profiles]
        clusters.append(f"{', '.join(node_pool_ips)}")
    return clusters

def list_virtual_networks(network_client):
    vnets = []
    for vnet in network_client.virtual_networks.list_all():
        subnet_ips = [subnet.address_prefix for subnet in vnet.subnets]
        vnets.append(f"{', '.join(subnet_ips)}")
    return vnets

def list_web_apps_with_ips(credential, subscription_id):
    web_client = WebSiteManagementClient(credential, subscription_id)
    web_apps = []
    for app in web_client.web_apps.list():
        default_hostname = app.default_host_name
        if default_hostname:
            web_apps.append(default_hostname)
    return web_apps

def list_application_gateways(network_client):
    gateways = []
    for agw in network_client.application_gateways.list_all():
        for frontend_ip_config in agw.frontend_ip_configurations:
            if frontend_ip_config.public_ip_address:
                public_ip_id = frontend_ip_config.public_ip_address.id
                resource_group = agw.id.split("/")[4]
                public_ip_name = public_ip_id.split("/")[-1]
                public_ip = network_client.public_ip_addresses.get(resource_group, public_ip_name).ip_address
                if public_ip:
                    gateways.append(public_ip)
    return gateways

def list_all_public_ips(network_client):
    ips = []
    for ip in network_client.public_ip_addresses.list_all():
        if ip.ip_address:
            ips.append(ip.ip_address)
    return ips


def export_to_json(data, filename):
    with open(filename + ".json", "w") as json_file:
        json.dump(data, json_file, indent=4)
    print(f"Data exported to {filename}.json")

def export_to_csv(data, filename):
    with open(filename + ".csv", "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        for service, resources in data.items():
            for resource in resources:
                writer.writerow([resource])
    print(f"Data exported to {filename}.csv")

def export_to_xml(data, filename):
    root = ET.Element("AzureResources")
    for service, resources in data.items():
        service_element = ET.SubElement(root, service)
        for resource in resources:
            resource_element = ET.SubElement(service_element, "Resource")
            resource_element.text = resource
    tree = ET.ElementTree(root)
    tree.write(filename + ".xml")
    print(f"Data exported to {filename}.xml")

def main():
    args = parse_arguments()
    credential = get_azure_credential(args.auth_method)
    
    compute_client = ComputeManagementClient(credential, args.subscription_id)
    storage_client = StorageManagementClient(credential, args.subscription_id)
    sql_client = SqlManagementClient(credential, args.subscription_id)
    container_client = ContainerServiceClient(credential, args.subscription_id)
    network_client = NetworkManagementClient(credential, args.subscription_id)
    
    services = {
        "Virtual Machines": list_virtual_machines(compute_client, network_client),
        "Storage Accounts": list_storage_accounts(storage_client),
        "SQL Servers": list_sql_servers(sql_client),
        "Kubernetes Clusters": list_kubernetes_clusters(container_client, network_client),
        "Virtual Networks": list_virtual_networks(network_client),
        "App Services": list_web_apps_with_ips(credential, args.subscription_id),
        "Application Gateways": list_application_gateways(network_client),
        "Public IP Addresses": list_all_public_ips(network_client)
    }

    for service, resources in services.items():
        for resource in resources:
            print(f"{resource}")
    
    if args.output_json:
        export_to_json(services, args.output_json)
    if args.output_csv:
        export_to_csv(services, args.output_csv)
    if args.output_xml:
        export_to_xml(services, args.output_xml)

if __name__ == "__main__":
    main()