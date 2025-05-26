import boto3
import botocore
import json # For handling policy documents if we extend later, and for pretty printing
import csv  # For CSV output (optional)

# Initialize S3 client
# Boto3 will automatically use the credentials configured via 'aws configure'
# You can specify a region if needed, but for many S3 operations, it's not required
# s3_client = boto3.client('s3', region_name='us-east-1')
s3_client = boto3.client('s3')

def check_bucket_security(bucket_name):
    """
    Checks various security settings for a given S3 bucket.
    Will return a dictionary with the findings.
    """
    print(f"\nAuditing Bucket: {bucket_name}")
    # Initialize a dictionary to store results for this bucket
    results = {'bucket_name': bucket_name}

    # 1. Check Public Access (ACLs & Policy Status)
    is_public_acl = False  # Assume not public by ACL by default
    is_public_policy = False # Assume not public by policy by default
    acl_check_error = None
    policy_check_error = None

    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            # Check for "AllUsers" (http://acs.amazonaws.com/groups/global/AllUsers)
            # or "AuthenticatedUsers" (http://acs.amazonaws.com/groups/global/AuthenticatedUsers)
            # For this check, we're primarily concerned with "AllUsers" for truly public.
            if grantee.get('Type') == 'Group' and \
            grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                # You could also check grant.get('Permission') here if you want to know
                # if it's READ, WRITE, READ_ACP, WRITE_ACP, FULL_CONTROL
                is_public_acl = True
                break # Found a public grant, no need to check further ACL grants
        results['public_via_acl'] = is_public_acl
        print(f"  Public via ACL: {is_public_acl}")

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        acl_check_error = f"ACL Check Error: {error_code}"
        print(f"  Error checking ACLs for {bucket_name}: {error_code}")
        results['public_via_acl'] = f"Error: {error_code}"

    try:
        policy_status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        # IsPublic will be true if the policy grants public access, false otherwise.
        is_public_policy = policy_status.get('PolicyStatus', {}).get('IsPublic', False)
        results['public_via_policy'] = is_public_policy
        print(f"  Public via Policy: {is_public_policy}")

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        # If there's no bucket policy, the API call itself might succeed but indicate no policy,
        # or it might throw 'NoSuchBucketPolicy'. The GetBucketPolicyStatus API is designed
        # to handle this more gracefully by returning IsPublic=false if no policy exists
        # or if the policy isn't public.
        # However, an explicit 'NoSuchBucketPolicy' usually means the bucket has no policy at all.
        if error_code == 'NoSuchBucketPolicy':
            is_public_policy = False # No policy means not public via policy
            results['public_via_policy'] = is_public_policy
            print(f"  Public via Policy: False (No policy attached)")
        else:
            policy_check_error = f"Policy Check Error: {error_code}"
            print(f"  Error checking policy status for {bucket_name}: {error_code}")
            results['public_via_policy'] = f"Error: {error_code}"

    # Overall public status
    results['is_public'] = is_public_acl or is_public_policy
    print(f"  Overall Public: {results['is_public']}")
    
    # 2. Check Default Encryption
    default_encryption_type = "Not Configured" # Assume not configured by default
    try:
        encryption_config = s3_client.get_bucket_encryption(Bucket=bucket_name)
        # The response structure is a list of rules, usually one for default encryption
        rules = encryption_config.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        if rules:
            # Get the algorithm from the first rule
            sse_algorithm = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
            if sse_algorithm:
                default_encryption_type = sse_algorithm
            # You could also check for KMSMasterKeyID if SSEAlgorithm is 'aws:kms'
            # kms_key_id = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID')
        results['default_encryption'] = default_encryption_type
        print(f"  Default Encryption: {default_encryption_type}")

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        # If no encryption configuration exists, AWS S3 API throws an error.
        # Common error code is 'ServerSideEncryptionConfigurationNotFoundError'
        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
            results['default_encryption'] = "Not Configured"
            print(f"  Default Encryption: Not Configured (No server-side encryption rules found)")
        else:
            print(f"  Error checking encryption for {bucket_name}: {error_code}")
            results['default_encryption'] = f"Error: {error_code}"
    # 3. Check Versioning and MFA Delete
    versioning_status = "Not Enabled" # Default if 'Status' key is missing or versioning never enabled
    mfa_delete_status = "Disabled"    # Default if 'MFADelete' key is missing or versioning not enabled

    try:
        versioning_config = s3_client.get_bucket_versioning(Bucket=bucket_name)

        # 'Status' can be 'Enabled', 'Suspended', or absent if never enabled.
        if 'Status' in versioning_config:
            versioning_status = versioning_config['Status']

        # 'MFADelete' can be 'Enabled' or 'Disabled'. It's only relevant if versioning is or was enabled.
        if 'MFADelete' in versioning_config:
            mfa_delete_status = versioning_config['MFADelete']

        results['versioning_status'] = versioning_status
        results['mfa_delete_status'] = mfa_delete_status
        print(f"  Versioning Status: {versioning_status}")
        print(f"  MFA Delete Status: {mfa_delete_status}")

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        print(f"  Error checking versioning/MFA Delete for {bucket_name}: {error_code}")
        results['versioning_status'] = f"Error: {error_code}"
        results['mfa_delete_status'] = f"Error: {error_code}"
    
    # 4. Check Server Access Logging
    logging_enabled = False # Assume not enabled by default
    logging_target_bucket = None
    logging_target_prefix = None

    try:
        logging_config = s3_client.get_bucket_logging(Bucket=bucket_name)

        if 'LoggingEnabled' in logging_config:
            logging_enabled = True
            logging_target_bucket = logging_config['LoggingEnabled'].get('TargetBucket')
            logging_target_prefix = logging_config['LoggingEnabled'].get('TargetPrefix')
            results['logging_enabled'] = logging_enabled
            results['logging_target_bucket'] = logging_target_bucket
            results['logging_target_prefix'] = logging_target_prefix
            print(f"  Logging Enabled: {logging_enabled}")
            print(f"    Target Bucket: {logging_target_bucket}")
            print(f"    Target Prefix: {logging_target_prefix}")
        else:
            # No 'LoggingEnabled' key means logging is not configured for this bucket.
            results['logging_enabled'] = logging_enabled
            print(f"  Logging Enabled: {logging_enabled}")

    except botocore.exceptions.ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        print(f"  Error checking logging for {bucket_name}: {error_code}")
        results['logging_enabled'] = f"Error: {error_code}"
        results['logging_target_bucket'] = "N/A due to error"
        results['logging_target_prefix'] = "N/A due to error"
        
    return results 

def main():
            """
            Main function to list buckets and orchestrate the audit.
            """
            all_bucket_results = []
            try:
                response = s3_client.list_buckets()
                print("Found the following buckets:")
                for bucket in response.get('Buckets', []):
                    print(f"- {bucket['Name']}")

                print("\nStarting security audit for each bucket...")
                for bucket in response.get('Buckets', []):
                    bucket_name = bucket['Name']
                    bucket_report = check_bucket_security(bucket_name)
                    all_bucket_results.append(bucket_report)

                # --- Output Processing ---
                if not all_bucket_results:
                    print("\nNo buckets found or no results to process.")
                    return # Exit if there's nothing to output

                print("\n\n--- Detailed Audit Summary (Console) ---")
                for res in all_bucket_results:
                    print(f"\nBucket: {res.get('bucket_name')}")
                    print(f"  Public via ACL: {res.get('public_via_acl')}")
                    print(f"  Public via Policy: {res.get('public_via_policy')}")
                    print(f"  Overall Public: {res.get('is_public')}")
                    print(f"  Default Encryption: {res.get('default_encryption')}")
                    print(f"  Versioning Status: {res.get('versioning_status')}")
                    print(f"  MFA Delete Status: {res.get('mfa_delete_status')}")
                    logging_status = res.get('logging_enabled')
                    print(f"  Logging Enabled: {logging_status}")
                    if logging_status is True or isinstance(logging_status, str) and "Error" not in logging_status : # Check if logging is actually enabled
                        if res.get('logging_target_bucket'): # Only print if True and target exists
                            print(f"    Target Bucket: {res.get('logging_target_bucket')}")
                            print(f"    Target Prefix: {res.get('logging_target_prefix')}")
                    elif isinstance(logging_status, str) and "Error" in logging_status: # Handle logging error string
                        pass # Error already printed during check

                # Define the desired order of columns for CSV
                # This ensures consistency in the CSV output
                field_names = [
                    'bucket_name', 'public_via_acl', 'public_via_policy', 'is_public',
                    'default_encryption', 'versioning_status', 'mfa_delete_status',
                    'logging_enabled', 'logging_target_bucket', 'logging_target_prefix'
                ]

                # Write to CSV file
                try:
                    with open('s3_security_audit_report.csv', 'w', newline='') as csvfile:
                        # Using DictWriter to handle missing keys gracefully by writing empty strings
                        writer = csv.DictWriter(csvfile, fieldnames=field_names, extrasaction='ignore')
                        writer.writeheader()
                        for data in all_bucket_results:
                            writer.writerow(data)
                    print("\n\nAudit report successfully saved to s3_security_audit_report.csv")
                except IOError:
                    print("Error: Could not write to s3_security_audit_report.csv. Check permissions or path.")
                except Exception as e:
                    print(f"An unexpected error occurred while writing CSV: {e}")

                # Write to JSON file
                try:
                    with open('s3_security_audit_report.json', 'w') as jsonfile:
                        json.dump(all_bucket_results, jsonfile, indent=4)
                    print("Audit report successfully saved to s3_security_audit_report.json")
                except IOError:
                    print("Error: Could not write to s3_security_audit_report.json. Check permissions or path.")
                except Exception as e:
                    print(f"An unexpected error occurred while writing JSON: {e}")

            except botocore.exceptions.NoCredentialsError: # MODIFIED HERE
                print("AWS credentials not found. Please configure your credentials (e.g., run 'aws configure').")
            except botocore.exceptions.ClientError as e: # Good to catch other potential Boto3 client errors here too
                print(f"An AWS client error occurred in main: {e}")
            except Exception as e:
                print(f"An unexpected error occurred in main: {e}")

if __name__ == '__main__':
    main()