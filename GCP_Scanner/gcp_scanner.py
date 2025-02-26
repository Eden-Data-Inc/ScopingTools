import argparse
import csv
import json
import xml.etree.ElementTree as ET
import google.auth
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

def parse_arguments():
    parser = argparse.ArgumentParser(description="GCP Resource Manager")
    parser.add_argument("--service_account_key", help="Path to GCP Service Account Key JSON file")
    parser.add_argument("--oauth_token", help="OAuth 2.0 access token")
    parser.add_argument("--project_id", required=True, help="GCP Project ID")
    parser.add_argument("--output-json", help="Output file name for JSON format (without extension)")
    parser.add_argument("--output-csv", help="Output file name for CSV format (without extension)")
    parser.add_argument("--output-xml", help="Output file name for XML format (without extension)")
    return parser.parse_args()

def get_gcp_client(service_name, version, credentials):
    return build(service_name, version, credentials=credentials)

def list_compute_instances(compute_client, project_id):
    request = compute_client.instances().aggregatedList(project=project_id)
    instances = []
    while request is not None:
        response = request.execute()
        for zone, data in response.get("items", {}).items():
            for instance in data.get("instances", []):
                external_ip = None
                for interface in instance.get("networkInterfaces", []):
                    if "accessConfigs" in interface:
                        for config in interface["accessConfigs"]:
                            if "natIP" in config:
                                external_ip = config["natIP"]
                if external_ip:
                    instances.append(external_ip)
        request = compute_client.instances().aggregatedList_next(previous_request=request, previous_response=response)
    return instances

def list_storage_buckets(storage_client, project_id):
    request = storage_client.buckets().list(project=project_id)
    response = request.execute()
    return [bucket["name"] for bucket in response.get("items", [])]

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
    root = ET.Element("GCPResources")
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
    credentials = None
    
    if args.service_account_key:
        credentials = service_account.Credentials.from_service_account_file(args.service_account_key)
    elif args.oauth_token:
        credentials = Credentials(token=args.oauth_token)
    else:
        print("Please provide authentication via service account key or OAuth token.")
        return
    
    services = {
        "compute": (list_compute_instances, "Compute Instances"),
        "storage": (list_storage_buckets, "Storage Buckets"),
    }
    
    clients = {service: get_gcp_client(service, "v1", credentials) for service in services}
    results = {}
    
    for service, (function, label) in services.items():
        results[label] = function(clients[service], args.project_id)
    
    for service, resources in results.items():
        for resource in resources:
            print(f"{resource}")
    
    if args.output_json:
        export_to_json(results, args.output_json)
    if args.output_csv:
        export_to_csv(results, args.output_csv)
    if args.output_xml:
        export_to_xml(results, args.output_xml)

if __name__ == "__main__":
    main()
