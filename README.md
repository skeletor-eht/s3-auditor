# S3 Bucket Security Auditor

## Description

This Python script uses the AWS SDK (Boto3) to scan S3 buckets in an AWS account for common security misconfigurations. It's designed to help AWS users and security professionals proactively identify potential risks and ensure their S3 storage is configured according to security best practices.

Manually checking S3 bucket configurations can be time-consuming and error-prone, especially in accounts with many buckets. This auditor automates the process, providing clear reports on key security settings.

---

## Features

The script checks each S3 bucket for the following configurations:

- **Public Access:**
  - Identifies if the bucket is public via Access Control Lists (ACLs).
  - Identifies if the bucket is public via its Bucket Policy.
  - Provides an overall public status.
- **Default Server-Side Encryption:**
  - Checks if default encryption (e.g., AES256 or aws:kms) is enabled for new objects.
- **Versioning:**
  - Determines if object versioning is `Enabled` or `Suspended`.
- **MFA Delete:**
  - Checks if MFA Delete is `Enabled` or `Disabled` (requires versioning to be enabled).
- **Server Access Logging:**
  - Verifies if server access logging is enabled to record requests made to the bucket.
  - If enabled, reports the target bucket and prefix for logs.

---

## Prerequisites

Before running the script, ensure you have the following:

1. **AWS Account:** Access to an AWS account.
2. **Python:** Python 3.6 or higher installed.
3. **Boto3:** The AWS SDK for Python.
4. **AWS CLI (Recommended):** For easy configuration of AWS credentials.
5. **IAM Permissions:** An IAM user or role with the necessary permissions to describe S3 bucket configurations.

---

## Setup & Installation

### 1. Get the Code

Clone or download the repository:  
`https://github.com/skeletor-eht/s3-auditor.git`

Then navigate into the project directory:

```bash
cd s3_security_audit
```

---

### 2. Create a Python Virtual Environment (Recommended)

In your project directory:

```bash
python -m venv venv
```

Activate the virtual environment:

- **macOS/Linux:**
  ```bash
  source venv/bin/activate
  ```

- **Windows (Command Prompt):**
  ```cmd
  venv\Scripts\activate.bat
  ```

- **Windows (PowerShell):**
  ```powershell
  .\venv\Scripts\Activate.ps1
  ```

---

### 3. Install Dependencies

With the virtual environment activated:

```bash
pip install boto3
```

---

### 4. Configure IAM Permissions

Create an IAM policy with the following permissions and attach it to the user or role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPolicy",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging"
      ],
      "Resource": "*"
    }
  ]
}
```

> ⚠️ This follows the principle of least privilege by granting only the read-only permissions the script needs.

---

### 5. Configure AWS Credentials

Use the AWS CLI to configure credentials:

```bash
aws configure
```

You’ll be prompted for:
- AWS Access Key ID
- AWS Secret Access Key
- Default region
- Output format

---

## Usage

Once setup is complete, run the script:

```bash
python s3_security_auditor.py
```

The script will:

- List all S3 buckets in your AWS account
- Check each for the security configurations listed above
- Print results to the console
- Generate two report files:
  - `s3_security_audit_report.csv`
  - `s3_security_audit_report.json`

---

## Output

### Console Output (Example):

```
Auditing Bucket: my-sample-bucket
  Public via ACL: False
  Public via Policy: False
  Overall Public: False
  Default Encryption: AES256
  Versioning Status: Enabled
  MFA Delete Status: Disabled
  Logging Enabled: True
    Target Bucket: my-log-bucket
    Target Prefix: logs/my-sample-bucket/
```

### Report Files:

- `s3_security_audit_report.csv`: Good for spreadsheets and reporting
- `s3_security_audit_report.json`: Good for automation or integration with dashboards

---

## Potential Enhancements

- Audit overly permissive bucket policies (not just public)
- Detect public objects inside private buckets
- Add support for assuming roles across multiple accounts
- Integrate with notification services (SNS, Slack)
- Add command-line arguments for specific buckets or regions
- Include remediation suggestions and better error messages

---

## Contributing

Contributions, issues, and feature requests are welcome.  
Fork the repo, make changes, and submit a pull request.
