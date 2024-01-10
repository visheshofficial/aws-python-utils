import boto3

# Specify the AWS CLI profile to use
aws_profile = 'shdevfa'

# Create a session using the specified profile
session = boto3.Session(profile_name=aws_profile)

# Set up the Athena client
client = session.client('athena', region_name='eu-central-1')


# Define the query
query = """
    SELECT column1, column2
    FROM your_table
    WHERE your_condition
"""

# Execute the query
response = client.start_query_execution(
    QueryString=query,
    QueryExecutionContext={
        'Database': 'your_database'
    },
    ResultConfiguration={
        'OutputLocation': 's3://your-s3-bucket/query-results/'
    }
)

# Get the query execution ID
query_execution_id = response['QueryExecutionId']

# Wait for the query to complete
response_wait = client.get_query_execution(
    QueryExecutionId=query_execution_id
)

while response_wait['QueryExecution']['Status']['State'] != 'SUCCEEDED':
    if response_wait['QueryExecution']['Status']['State'] == 'FAILED':
        raise Exception("Query failed to run with error: %s" % response_wait['QueryExecution']['Status']['StateChangeReason'])
    response_wait = client.get_query_execution(
        QueryExecutionId=query_execution_id
    )

# Get the query results
query_results = client.get_query_results(
    QueryExecutionId=query_execution_id
)

# Extract the result rows
header = [col['Name'] for col in query_results['ResultSet']['ResultSetMetadata']['ColumnInfo']]
rows = [list(row['Data'].values()) for row in query_results['ResultSet']['Rows'][1:]]

# Export the result as a CSV file
with open('query_results.csv', 'w') as csv_file:
    csv_file.write(','.join(header) + '\n')
    for row in rows:
        csv_file.write(','.join(row) + '\n')

print("Query results exported to 'query_results.csv'")
