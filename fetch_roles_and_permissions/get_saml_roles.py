import boto3
from tabulate import tabulate
import os

# profile_name = "ivdevdo"
profile_name = "AdministratorAccess-337941034038"
table_fmt = "simple_grid"

aws_account_number = None
aws_session = None
path = None


def get_account_info():
    # Initialize Boto3 STS client
    sts_client = aws_session.client("sts")

    try:
        # Get AWS account ID
        response = sts_client.get_caller_identity()
        return response["Account"]

    except Exception as e:
        print("Failed to get account info:", str(e))
        return None


def is_saml_role(trust_policy):
    for statement in trust_policy.get("Statement", []):
        if (
                statement.get("Effect") == "Allow"
                and statement.get("Action") == "sts:AssumeRoleWithSAML"
                and statement.get("Principal", {}).get("Federated")
        ):
            return True
    return False


def get_permissions_for_attached_policy(policy, role_name, account_id):
    policy_document = policy["PolicyDocument"]["PolicyVersion"]["Document"]
    policy_name = policy["PolicyName"]
    permissions = []

    for statement in policy_document["Statement"]:
        action = statement["Action"]
        if isinstance(action, str):
            action = [action]  # Convert single string to a list
        effect = statement["Effect"]
        resource = statement.get("Resource", "N/A")
        permissions.append([action, effect, resource])

    flat_actions = [action for perm in permissions for action in perm[0]]

    table_data = []
    for action, effect, resource in permissions:
        table_data.append(
            [
                account_id,
                role_name,
                policy_name,
                "\n".join(sorted(action)),
                effect,
                resource,
            ]
        )

    headers = [
        "Account Number",
        "Role Name",
        "Policy Name",
        "Actions",
        "Effect",
        "Resource",
    ]
    # print(tabulate(table_data, headers=headers, tablefmt=table_fmt))
    with open(os.path.join(path, role_name + '-attached-permissions.txt'), 'w') as f:
        f.write(tabulate(table_data, headers=headers, tablefmt=table_fmt))


def get_permissions_for_inline_policy(policy, role_name, account_id):
    policy_document = policy["PolicyDocument"]
    policy_name = policy["PolicyName"]
    permissions = []

    for statement in policy_document["Statement"]:
        action = statement["Action"]
        if isinstance(action, str):
            action = [action]  # Convert single string to a list
        effect = statement["Effect"]
        resource = statement.get("Resource", "N/A")
        permissions.append([action, effect, resource])

    flat_actions = [action for perm in permissions for action in perm[0]]
    action_list = ", ".join(sorted(set(flat_actions)))

    table_data = []
    for action, effect, resource in permissions:
        table_data.append(
            [
                account_id,
                role_name,
                policy_name,
                "\n".join(sorted(action)),
                effect,
                resource,
            ]
        )

    headers = [
        "Account Number",
        "Role Name",
        "Policy Name",
        "Actions",
        "Effect",
        "Resource",
    ]
    with open(os.path.join(path, role_name + '-inline-permissions.txt'), 'w') as f:
        f.write(tabulate(table_data, headers=headers, tablefmt=table_fmt))


def get_roles_and_policies(profile_name):
    # Table header
    headers = [
        "Account Number", "Role Name", "Attached Policies", "Inline Policies"
    ]
    role_and_policies = list()
    iam_client = aws_session.client("iam")

    try:
        table_data = []

        roles = []
        paginator = iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            roles.extend(page["Roles"])


        # Iterate over each role to get attached policies
        for role in roles:
            role_name = role["RoleName"]

            if not is_saml_role(role.get("AssumeRolePolicyDocument", {})):
                continue

            # Get a list of policies attached to the role
            attached_policies = get_attached_policies_with_name(role_name)
            # Get a list of inline policies attached to the role
            inline_policies = get_inline_policies(role_name)

            # tabulate the data
            table_data.append(
                [
                    aws_account_number,
                    role_name,
                    "\n".join(sorted(x["PolicyName"] for x in attached_policies))
                    or "None",
                    "\n".join(sorted(x["PolicyName"] for x in inline_policies))
                    or "None",
                ]
            )
            role_and_policies.append(
                {
                    "attached_policies": attached_policies,
                    "inline_policies": inline_policies,
                    "role_name": role_name,
                    "account_id": aws_account_number,
                }
            )

        with open(os.path.join(path, 'roles_and_policies_summary.txt'), 'w') as f:
            f.write(tabulate(table_data, headers=headers, tablefmt=table_fmt))

    except Exception as e:
        print("An error occurred:", str(e))

    return role_and_policies


def get_inline_policies(role_name):
    iam_client = aws_session.client("iam")

    try:
        response = iam_client.list_role_policies(RoleName=role_name)
        inline_policies = []
        for policy_name in response["PolicyNames"]:
            policy = iam_client.get_role_policy(
                RoleName=role_name, PolicyName=policy_name
            )
            inline_policies.append(policy)
        return inline_policies

    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"The role '{role_name}' does not exist.")
        return []

    except Exception as e:
        print(f"Error: {e}")
        return []


def get_attached_policies_with_name(role_name):
    iam_client = aws_session.client("iam")
    try:
        response = iam_client.list_attached_role_policies(RoleName=role_name)
        attached_policies = []

        for attached_policy in response["AttachedPolicies"]:
            policy = iam_client.get_policy(PolicyArn=attached_policy["PolicyArn"])
            policy_document = iam_client.get_policy_version(
                PolicyArn=policy["Policy"]["Arn"],
                VersionId=policy["Policy"]["DefaultVersionId"],
            )
            attached_policies.append(
                {
                    "RoleName": role_name,
                    "PolicyName": attached_policy["PolicyName"],
                    "PolicyDocument": policy_document,
                }
            )
        return attached_policies

    except iam_client.exceptions.NoSuchEntityException as e:
        print(f"The role '{role_name}' does not exist.")
        return []

    except Exception as e:
        print(f"Error: {e}")
        return []


if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="Retrieve AWS IAM roles and their associated policies.")
    # parser.add_argument('--profile', type=str, required=True, help='AWS profile name to use.')
    # args = parser.parse_args()

    # Initialize Boto3 IAM client
    aws_session = boto3.Session(profile_name=profile_name)
    aws_account_number = get_account_info()
    print("AWS Account Number: " + aws_account_number + "\nProfile: " + profile_name)

    # specify the path for the directory – make sure to surround it with quotation marks
    path = './' + aws_account_number

    # create new single directory

    os.makedirs(path, exist_ok=True)  # Create the directory if it doesn't exist

    role_and_policies = get_roles_and_policies(profile_name)

    for role_and_policy in role_and_policies:
        for attached_policy in role_and_policy["attached_policies"]:
            get_permissions_for_attached_policy(
                attached_policy,
                role_and_policy["role_name"],
                role_and_policy["account_id"],
            )
        for inline_policy in role_and_policy["inline_policies"]:
            get_permissions_for_inline_policy(
                inline_policy,
                role_and_policy["role_name"],
                role_and_policy["account_id"],
            )
