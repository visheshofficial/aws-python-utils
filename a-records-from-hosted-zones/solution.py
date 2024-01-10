import boto3
from tabulate import tabulate

# Specify the AWS CLI profile to use
# aws_profile = 'sdwprodfa'
aws_profile = 'snasa'

# Create a session using the specified profile
session = boto3.Session(profile_name=aws_profile)

def list_a_and_cname_records():
    # Initialize the Route 53 client
    client = session.client('route53')

    # List all hosted zones in the AWS account
    hosted_zones = client.list_hosted_zones()

    # Initialize a list to store the table data
    table_data = []

    # Iterate through the hosted zones
    for hosted_zone in hosted_zones['HostedZones']:
        zone_id = hosted_zone['Id'].split('/')[-1]
        zone_name = hosted_zone['Name']

        # List resource record sets for the hosted zone
        response = client.list_resource_record_sets(HostedZoneId=zone_id)

        # Iterate through resource record sets and filter A and CNAME records
        for record_set in response['ResourceRecordSets']:
            if record_set['Type'] in ['A', 'CNAME']:
                record_data = {
                    'Hosted Zone': zone_name,
                    'Record Name': record_set['Name'],
                    'Record Type': record_set['Type'],
                    'Record Value': ', '.join([record['Value'] for record in record_set.get('ResourceRecords', [])])
                }
                table_data.append(record_data)

    # Display the table
    if table_data:
        print(tabulate(table_data, headers='keys', tablefmt='grid'))
    else:
        print("No A or CNAME records found.")

if __name__ == "__main__":
    list_a_and_cname_records()
