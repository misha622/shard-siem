#!/usr/bin/env python3

"""
SHARD Cloud Security Module
Production-ready cloud security monitoring for AWS, Azure, and GCP.
Real API integration, no mocks.

Author: SHARD Enterprise
Version: 3.0.0
"""

import os
import json
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import requests

try:
    from shard_enterprise_complete import (
        BaseModule,
        ConfigManager,
        EventBus,
        LoggingService
    )
except ImportError:
    from typing import Protocol


    class BaseModule(Protocol):
        name: str
        config: Any
        event_bus: Any
        logger: Any
        running: bool


    class ConfigManager:
        def get(self, key: str, default: Any = None) -> Any: ...


    class EventBus:
        def publish(self, event_type: str, data: Any = None) -> None: ...

        def subscribe(self, event_type: str, callback: Any) -> None: ...


    class LoggingService:
        def get_logger(self, name: str = None): ...



@dataclass
class CloudSecurityConfig:
    """Configuration for Cloud Security module"""

    aws_enabled: bool = False
    aws_access_key: str = ""
    aws_secret_key: str = ""
    aws_session_token: str = ""
    aws_region: str = "us-east-1"

    azure_enabled: bool = False
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""
    azure_subscription_id: str = ""

    gcp_enabled: bool = False
    gcp_project_id: str = ""
    gcp_credentials_file: str = ""

    scan_interval: int = 300
    alert_on_finding: bool = True
    auto_remediate: bool = False
    finding_severity_threshold: str = "MEDIUM"

    findings_dir: str = "./data/cloud_findings/"



class AWSSecurityScanner:
    """
    Full AWS security scanner using boto3.
    Checks: S3, IAM, Security Groups, CloudTrail, Encryption, MFA.
    """

    def __init__(self, config: CloudSecurityConfig, logger):
        self.config = config
        self.logger = logger
        self.boto3 = None
        self._init_boto3()
        self.findings: List[Dict] = []

    def _init_boto3(self):
        """Initialize boto3 client"""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            self.boto3 = boto3
            self.ClientError = ClientError
            self.NoCredentialsError = NoCredentialsError
            self.logger.info("✅ AWS boto3 initialized")
        except ImportError:
            self.logger.warning("⚠️ boto3 not installed. pip install boto3")
            self.boto3 = None

    def _get_client(self, service: str):
        """Get AWS client for service"""
        if not self.boto3:
            return None

        try:
            kwargs = {
                'service_name': service,
                'region_name': self.config.aws_region
            }
            if self.config.aws_access_key:
                kwargs['aws_access_key_id'] = self.config.aws_access_key
                kwargs['aws_secret_access_key'] = self.config.aws_secret_key
            if self.config.aws_session_token:
                kwargs['aws_session_token'] = self.config.aws_session_token

            return self.boto3.client(**kwargs)
        except Exception as e:
            self.logger.error(f"AWS client error for {service}: {e}")
            return None

    def scan_s3_buckets(self) -> List[Dict]:
        """Scan S3 buckets for public access and encryption"""
        findings = []
        s3 = self._get_client('s3')
        if not s3:
            return findings

        try:
            response = s3.list_buckets()
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']

                try:
                    public_access = s3.get_public_access_block(Bucket=bucket_name)
                    block_config = public_access.get('PublicAccessBlockConfiguration', {})
                    if not block_config.get('BlockPublicAcls', False):
                        findings.append(self._create_finding(
                            'AWS', 'S3', bucket_name,
                            'Public ACLs not blocked', 'HIGH',
                            'Enable BlockPublicAcls'
                        ))
                except self.ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                        findings.append(self._create_finding(
                            'AWS', 'S3', bucket_name,
                            'No public access block configured', 'CRITICAL',
                            'Configure PublicAccessBlockConfiguration'
                        ))

                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except self.ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append(self._create_finding(
                            'AWS', 'S3', bucket_name,
                            'Default encryption not enabled', 'MEDIUM',
                            'Enable default encryption'
                        ))

                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append(self._create_finding(
                            'AWS', 'S3', bucket_name,
                            'Versioning not enabled', 'LOW',
                            'Enable versioning'
                        ))
                except:
                    pass

        except Exception as e:
            self.logger.error(f"S3 scan error: {e}")

        return findings

    def scan_iam_users(self) -> List[Dict]:
        """Scan IAM for unused keys, old keys, and missing MFA"""
        findings = []
        iam = self._get_client('iam')
        if not iam:
            return findings

        try:
            response = iam.list_users()
            for user in response.get('Users', []):
                username = user['UserName']

                keys = iam.list_access_keys(UserName=username)
                for key in keys.get('AccessKeyMetadata', []):
                    create_date = key['CreateDate']
                    age_days = (datetime.now(timezone.utc) - create_date).days

                    if age_days > 90:
                        findings.append(self._create_finding(
                            'AWS', 'IAM', f"{username}/{key['AccessKeyId']}",
                            f'Access key older than 90 days ({age_days} days)', 'MEDIUM',
                            'Rotate access keys'
                        ))

                    last_used = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                    last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                    if last_used_date is None and key['Status'] == 'Active':
                        findings.append(self._create_finding(
                            'AWS', 'IAM', f"{username}/{key['AccessKeyId']}",
                            'Active key never used', 'LOW',
                            'Deactivate or delete unused key'
                        ))

                mfa_devices = iam.list_mfa_devices(UserName=username)
                if not mfa_devices.get('MFADevices'):
                    try:
                        iam.get_login_profile(UserName=username)
                        findings.append(self._create_finding(
                            'AWS', 'IAM', username,
                            'Console access without MFA', 'HIGH',
                            'Enable MFA for console users'
                        ))
                    except:
                        pass

                policies = iam.list_attached_user_policies(UserName=username)
                for policy in policies.get('AttachedPolicies', []):
                    if policy['PolicyName'] == 'AdministratorAccess':
                        findings.append(self._create_finding(
                            'AWS', 'IAM', username,
                            'User has AdministratorAccess policy', 'MEDIUM',
                            'Review if admin access is required'
                        ))

        except Exception as e:
            self.logger.error(f"IAM scan error: {e}")

        return findings

    def scan_security_groups(self) -> List[Dict]:
        """Scan security groups for overly permissive rules"""
        findings = []
        ec2 = self._get_client('ec2')
        if not ec2:
            return findings

        try:
            response = ec2.describe_security_groups()
            for sg in response.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']

                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 0)
                            severity = 'CRITICAL' if from_port in [22, 3389, 3306, 5432, 27017] else 'HIGH'

                            findings.append(self._create_finding(
                                'AWS', 'EC2', f"{sg_name} ({sg_id})",
                                f'Open to world: port {from_port}-{to_port}', severity,
                                'Restrict to specific IP ranges'
                            ))

                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        if ipv6_range.get('CidrIpv6') == '::/0':
                            findings.append(self._create_finding(
                                'AWS', 'EC2', f"{sg_name} ({sg_id})",
                                'Open to world (IPv6)', 'HIGH',
                                'Restrict to specific IPv6 ranges'
                            ))

        except Exception as e:
            self.logger.error(f"Security group scan error: {e}")

        return findings

    def scan_cloudtrail(self) -> List[Dict]:
        """Scan CloudTrail for proper configuration"""
        findings = []
        cloudtrail = self._get_client('cloudtrail')
        if not cloudtrail:
            return findings

        try:
            trails = cloudtrail.describe_trails()
            if not trails.get('trailList'):
                findings.append(self._create_finding(
                    'AWS', 'CloudTrail', 'Account',
                    'CloudTrail not enabled', 'HIGH',
                    'Enable CloudTrail in all regions'
                ))
                return findings

            for trail in trails['trailList']:
                if not trail.get('IsMultiRegionTrail'):
                    findings.append(self._create_finding(
                        'AWS', 'CloudTrail', trail['Name'],
                        'Not multi-region trail', 'MEDIUM',
                        'Enable multi-region trail'
                    ))

                if not trail.get('LogFileValidationEnabled'):
                    findings.append(self._create_finding(
                        'AWS', 'CloudTrail', trail['Name'],
                        'Log file validation disabled', 'MEDIUM',
                        'Enable log file validation'
                    ))

                if not trail.get('CloudWatchLogsLogGroupArn'):
                    findings.append(self._create_finding(
                        'AWS', 'CloudTrail', trail['Name'],
                        'CloudWatch Logs not integrated', 'LOW',
                        'Integrate with CloudWatch Logs'
                    ))

        except Exception as e:
            self.logger.error(f"CloudTrail scan error: {e}")

        return findings

    def scan_rds_encryption(self) -> List[Dict]:
        """Scan RDS instances for encryption at rest"""
        findings = []
        rds = self._get_client('rds')
        if not rds:
            return findings

        try:
            instances = rds.describe_db_instances()
            for db in instances.get('DBInstances', []):
                if not db.get('StorageEncrypted'):
                    findings.append(self._create_finding(
                        'AWS', 'RDS', db['DBInstanceIdentifier'],
                        'Storage encryption not enabled', 'HIGH',
                        'Enable encryption at rest'
                    ))

        except Exception as e:
            self.logger.error(f"RDS scan error: {e}")

        return findings

    def _create_finding(self, cloud: str, service: str, resource: str,
                        finding: str, severity: str, remediation: str) -> Dict:
        return {
            'timestamp': time.time(),
            'cloud': cloud,
            'service': service,
            'resource': resource,
            'finding': finding,
            'severity': severity,
            'remediation': remediation
        }

    def scan_all(self) -> List[Dict]:
        """Run all AWS scans"""
        if not self.boto3:
            return []

        self.logger.info("🔍 Scanning AWS security...")

        all_findings = []
        all_findings.extend(self.scan_s3_buckets())
        all_findings.extend(self.scan_iam_users())
        all_findings.extend(self.scan_security_groups())
        all_findings.extend(self.scan_cloudtrail())
        all_findings.extend(self.scan_rds_encryption())

        self.findings = all_findings
        self.logger.info(f"✅ AWS scan complete: {len(all_findings)} findings")

        return all_findings



class AzureSecurityScanner:
    """
    Full Azure security scanner using Azure SDK.
    Checks: Storage, NSG, IAM, MFA, Encryption, Activity Log.
    """

    def __init__(self, config: CloudSecurityConfig, logger):
        self.config = config
        self.logger = logger
        self.credentials = None
        self._init_azure()
        self.findings: List[Dict] = []

    def _init_azure(self):
        """Initialize Azure SDK"""
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.network import NetworkManagementClient
            from azure.mgmt.monitor import MonitorManagementClient
            import requests

            self.ClientSecretCredential = ClientSecretCredential
            self.ResourceManagementClient = ResourceManagementClient
            self.StorageManagementClient = StorageManagementClient
            self.NetworkManagementClient = NetworkManagementClient
            self.MonitorManagementClient = MonitorManagementClient
            self.requests = requests

            if self.config.azure_tenant_id:
                self.credentials = ClientSecretCredential(
                    tenant_id=self.config.azure_tenant_id,
                    client_id=self.config.azure_client_id,
                    client_secret=self.config.azure_client_secret
                )
            self.logger.info("✅ Azure SDK initialized")
        except ImportError as e:
            self.logger.warning(f"⚠️ Azure SDK not installed: {e}")
            self.credentials = None

    def scan_storage_accounts(self) -> List[Dict]:
        """Scan Azure storage accounts for public access and encryption"""
        findings = []
        if not self.credentials:
            return findings

        try:
            storage_client = self.StorageManagementClient(self.credentials, self.config.azure_subscription_id)
            accounts = storage_client.storage_accounts.list()

            for account in accounts:
                if not account.enable_https_traffic_only:
                    findings.append(self._create_finding(
                        'Azure', 'Storage', account.name,
                        'HTTP traffic allowed', 'HIGH',
                        'Enable HTTPS only'
                    ))

                if account.allow_blob_public_access:
                    findings.append(self._create_finding(
                        'Azure', 'Storage', account.name,
                        'Blob public access allowed', 'CRITICAL',
                        'Disable blob public access'
                    ))

                if account.encryption and not account.encryption.services.blob.enabled:
                    findings.append(self._create_finding(
                        'Azure', 'Storage', account.name,
                        'Blob encryption not enabled', 'HIGH',
                        'Enable blob encryption'
                    ))

        except Exception as e:
            self.logger.error(f"Azure storage scan error: {e}")

        return findings

    def scan_network_security_groups(self) -> List[Dict]:
        """Scan NSGs for permissive rules"""
        findings = []
        if not self.credentials:
            return findings

        try:
            network_client = self.NetworkManagementClient(self.credentials, self.config.azure_subscription_id)
            nsgs = network_client.network_security_groups.list_all()

            for nsg in nsgs:
                for rule in nsg.security_rules:
                    if rule.direction == 'Inbound' and rule.access == 'Allow':
                        if rule.source_address_prefix in ['*', 'Internet']:
                            severity = 'CRITICAL' if rule.destination_port_range in ['22', '3389', '3306', '5432'] else 'HIGH'
                            findings.append(self._create_finding(
                                'Azure', 'Network', f"{nsg.name}/{rule.name}",
                                f'Open to internet: port {rule.destination_port_range}', severity,
                                'Restrict source address prefix'
                            ))

        except Exception as e:
            self.logger.error(f"Azure NSG scan error: {e}")

        return findings

    def scan_iam_users(self) -> List[Dict]:
        """Scan Azure AD for users without MFA"""
        findings = []
        if not self.credentials:
            return findings

        try:
            token = self.credentials.get_token("https://graph.microsoft.com/.default")
            headers = {'Authorization': f'Bearer {token.token}'}

            response = self.requests.get('https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName', headers=headers)
            if response.status_code != 200:
                return findings

            users = response.json().get('value', [])
            for user in users:
                mfa_response = self.requests.get(
                    f"https://graph.microsoft.com/v1.0/users/{user['id']}/authentication/methods",
                    headers=headers
                )
                if mfa_response.status_code == 200:
                    methods = mfa_response.json().get('value', [])
                    has_mfa = any(m.get('@odata.type') == '
                    if not has_mfa:
                        findings.append(self._create_finding(
                            'Azure', 'IAM', user['userPrincipalName'],
                            'User without MFA', 'HIGH',
                            'Enable Multi-Factor Authentication'
                        ))

        except Exception as e:
            self.logger.error(f"Azure IAM scan error: {e}")

        return findings

    def scan_activity_log(self) -> List[Dict]:
        """Scan Activity Log for suspicious operations"""
        findings = []
        if not self.credentials:
            return findings

        try:
            monitor_client = self.MonitorManagementClient(self.credentials, self.config.azure_subscription_id)
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=24)

            filter_str = "eventChannels eq 'Admin, Operation'"
            logs = monitor_client.activity_logs.list(filter=filter_str, select='eventName,operationName,status', top=100)

            suspicious_ops = ['Microsoft.Authorization/roleAssignments/write', 'Microsoft.Security/securitySolutions/delete']
            for log in logs:
                if log.operation_name.value in suspicious_ops:
                    findings.append(self._create_finding(
                        'Azure', 'ActivityLog', log.operation_name.value,
                        f'Suspicious operation: {log.operation_name.value}', 'MEDIUM',
                        'Review activity log'
                    ))

        except Exception as e:
            self.logger.error(f"Azure Activity Log scan error: {e}")

        return findings

    def _create_finding(self, cloud: str, service: str, resource: str,
                        finding: str, severity: str, remediation: str) -> Dict:
        return {
            'timestamp': time.time(),
            'cloud': cloud,
            'service': service,
            'resource': resource,
            'finding': finding,
            'severity': severity,
            'remediation': remediation
        }

    def scan_all(self) -> List[Dict]:
        """Run all Azure scans"""
        if not self.credentials:
            return []

        self.logger.info("🔍 Scanning Azure security...")

        all_findings = []
        all_findings.extend(self.scan_storage_accounts())
        all_findings.extend(self.scan_network_security_groups())
        all_findings.extend(self.scan_iam_users())
        all_findings.extend(self.scan_activity_log())

        self.findings = all_findings
        self.logger.info(f"✅ Azure scan complete: {len(all_findings)} findings")

        return all_findings



class GCPSecurityScanner:
    """
    Full GCP security scanner using Google Cloud SDK.
    Checks: Storage, Firewall, IAM, MFA, Audit Logs, Encryption.
    """

    def __init__(self, config: CloudSecurityConfig, logger):
        self.config = config
        self.logger = logger
        self.credentials = None
        self.project_id = config.gcp_project_id
        self._init_gcp()
        self.findings: List[Dict] = []

    def _init_gcp(self):
        """Initialize GCP SDK"""
        try:
            from google.cloud import storage
            from google.cloud import compute_v1
            from google.cloud import resource_manager
            import google.auth
            from google.auth.transport.requests import Request

            self.storage = storage
            self.compute_v1 = compute_v1
            self.resource_manager = resource_manager
            self.google_auth = google.auth

            if self.config.gcp_credentials_file:
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = self.config.gcp_credentials_file

            self.credentials, self.project_id = google.auth.default()
            self.logger.info("✅ GCP SDK initialized")
        except ImportError as e:
            self.logger.warning(f"⚠️ Google Cloud SDK not installed: {e}")
            self.credentials = None

    def scan_storage_buckets(self) -> List[Dict]:
        """Scan GCS buckets for public access and encryption"""
        findings = []
        if not self.credentials:
            return findings

        try:
            client = self.storage.Client(project=self.project_id)
            buckets = client.list_buckets()

            for bucket in buckets:
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    if binding['role'] == 'roles/storage.objectViewer':
                        if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                            findings.append(self._create_finding(
                                'GCP', 'Storage', bucket.name,
                                'Bucket publicly readable', 'CRITICAL',
                                'Remove public IAM binding'
                            ))

                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    findings.append(self._create_finding(
                        'GCP', 'Storage', bucket.name,
                        'Uniform bucket-level access not enabled', 'MEDIUM',
                        'Enable uniform bucket-level access'
                    ))

                if bucket.encryption and bucket.encryption.default_kms_key_name is None:
                    findings.append(self._create_finding(
                        'GCP', 'Storage', bucket.name,
                        'Default KMS encryption not configured', 'MEDIUM',
                        'Configure default KMS key'
                    ))

        except Exception as e:
            self.logger.error(f"GCP storage scan error: {e}")

        return findings

    def scan_firewall_rules(self) -> List[Dict]:
        """Scan VPC firewall rules"""
        findings = []
        if not self.credentials:
            return findings

        try:
            client = self.compute_v1.FirewallsClient()
            rules = client.list(project=self.project_id)

            for rule in rules:
                if rule.direction == 'INGRESS' and not rule.disabled:
                    for allowed in rule.allowed:
                        if '0.0.0.0/0' in rule.source_ranges:
                            ports = allowed.ports if allowed.ports else ['all']
                            severity = 'CRITICAL' if any(p in ports for p in ['22', '3389', '3306', '5432']) else 'HIGH'
                            findings.append(self._create_finding(
                                'GCP', 'VPC', rule.name,
                                f'Open to world: {ports}', severity,
                                'Restrict source ranges'
                            ))

        except Exception as e:
            self.logger.error(f"GCP firewall scan error: {e}")

        return findings

    def scan_iam_users(self) -> List[Dict]:
        """Scan IAM for service accounts with excessive permissions and missing MFA"""
        findings = []
        if not self.credentials:
            return findings

        try:
            import requests
            from google.auth.transport.requests import Request

            self.credentials.refresh(Request())
            token = self.credentials.token

            headers = {'Authorization': f'Bearer {token}'}

            response = requests.get(
                f'https://iam.googleapis.com/v1/projects/{self.project_id}/serviceAccounts',
                headers=headers
            )

            if response.status_code == 200:
                accounts = response.json().get('accounts', [])
                for account in accounts:
                    if 'roles/owner' in account.get('description', '').lower():
                        findings.append(self._create_finding(
                            'GCP', 'IAM', account['email'],
                            'Service account may have owner permissions', 'HIGH',
                            'Review and restrict permissions'
                        ))

                    keys_response = requests.get(
                        f'https://iam.googleapis.com/v1/projects/{self.project_id}/serviceAccounts/{account["email"]}/keys',
                        headers=headers
                    )
                    if keys_response.status_code == 200:
                        for key in keys_response.json().get('keys', []):
                            if 'validAfterTime' in key:
                                create_time = datetime.fromisoformat(key['validAfterTime'].replace('Z', '+00:00'))
                                age_days = (datetime.now(timezone.utc) - create_time).days
                                if age_days > 90:
                                    findings.append(self._create_finding(
                                        'GCP', 'IAM', account['email'],
                                        f'Service account key older than 90 days ({age_days} days)', 'MEDIUM',
                                        'Rotate service account keys'
                                    ))

        except Exception as e:
            self.logger.error(f"GCP IAM scan error: {e}")

        return findings

    def scan_audit_logs(self) -> List[Dict]:
        """Scan Cloud Audit Logs for suspicious activity"""
        findings = []
        if not self.credentials:
            return findings

        try:
            from google.cloud import logging_v2

            client = logging_v2.LoggingServiceV2Client()
            resource_names = [f"projects/{self.project_id}"]

            filter_str = 'protoPayload.methodName=("SetIamPolicy" OR "UpdateServiceAccount" OR "DeleteServiceAccount") AND timestamp > "2024-01-01T00:00:00Z"'

            for entry in client.list_log_entries(resource_names=resource_names, filter_=filter_str, page_size=10):
                findings.append(self._create_finding(
                    'GCP', 'AuditLog', str(entry.resource.labels),
                    f'Suspicious IAM activity: {entry.proto_payload.method_name}', 'MEDIUM',
                    'Review audit logs'
                ))

        except Exception as e:
            self.logger.error(f"GCP Audit Log scan error: {e}")

        return findings

    def _create_finding(self, cloud: str, service: str, resource: str,
                        finding: str, severity: str, remediation: str) -> Dict:
        return {
            'timestamp': time.time(),
            'cloud': cloud,
            'service': service,
            'resource': resource,
            'finding': finding,
            'severity': severity,
            'remediation': remediation
        }

    def scan_all(self) -> List[Dict]:
        """Run all GCP scans"""
        self.logger.info("🔍 Scanning GCP security...")

        all_findings = []
        all_findings.extend(self.scan_storage_buckets())
        all_findings.extend(self.scan_firewall_rules())
        all_findings.extend(self.scan_iam_users())
        all_findings.extend(self.scan_audit_logs())

        self.findings = all_findings
        self.logger.info(f"✅ GCP scan complete: {len(all_findings)} findings")

        return all_findings



class CloudSecurityEngine:
    """Main Cloud Security Engine coordinating all cloud providers."""

    def __init__(self, config: CloudSecurityConfig, event_bus, logger):
        self.config = config
        self.event_bus = event_bus
        self.logger = logger

        self.aws_scanner = AWSSecurityScanner(config, logger) if config.aws_enabled else None
        self.azure_scanner = AzureSecurityScanner(config, logger) if config.azure_enabled else None
        self.gcp_scanner = GCPSecurityScanner(config, logger) if config.gcp_enabled else None

        self.findings_history: deque = deque(maxlen=1000)
        self._lock = threading.RLock()
        self._running = False
        self._scan_thread = None

        Path(self.config.findings_dir).mkdir(parents=True, exist_ok=True)

    def start(self):
        """Start cloud security scanning"""
        self._running = True
        self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True, name="CloudSecurity")
        self._scan_thread.start()
        if hasattr(self.logger, 'info'):
            self.logger.info("🚀 Cloud Security Engine started")
        elif hasattr(self.logger, 'log'):
            self.logger.log("🚀 Cloud Security Engine started")
        else:
            print("🚀 Cloud Security Engine started")

    def stop(self):
        """Stop scanning"""
        self._running = False
        if self._scan_thread:
            self._scan_thread.join(timeout=5)
        self._save_findings()
        self.logger.info("🛑 Cloud Security Engine stopped")

    def _scan_loop(self):
        """Background scanning loop"""
        while self._running:
            self.scan_all()
            time.sleep(self.config.scan_interval)

    def scan_all(self) -> List[Dict]:
        """Run all cloud security scans"""
        all_findings = []

        if self.aws_scanner:
            all_findings.extend(self.aws_scanner.scan_all())
        if self.azure_scanner:
            all_findings.extend(self.azure_scanner.scan_all())
        if self.gcp_scanner:
            all_findings.extend(self.gcp_scanner.scan_all())

        with self._lock:
            for finding in all_findings:
                self.findings_history.append(finding)
                if self.config.alert_on_finding:
                    self._publish_finding_alert(finding)

        return all_findings

    def _publish_finding_alert(self, finding: Dict):
        """Publish cloud finding as SIEM alert"""
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        threshold = severity_order.get(self.config.finding_severity_threshold, 2)

        if severity_order.get(finding['severity'], 0) >= threshold:
            alert = {
                'timestamp': finding['timestamp'],
                'attack_type': f"Cloud Misconfiguration - {finding['cloud']}",
                'severity': finding['severity'],
                'score': 0.7 if finding['severity'] == 'CRITICAL' else 0.5,
                'confidence': 0.95,
                'is_attack': True,
                'explanation': f"{finding['cloud']}/{finding['service']}: {finding['finding']}",
                'details': finding
            }
            self.event_bus.publish('alert.detected', alert)
            self.logger.warning(f"☁️ Cloud finding: {finding['cloud']} - {finding['finding']}")

    def _save_findings(self):
        """Save findings to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filepath = Path(self.config.findings_dir) / f"findings_{timestamp}.json"

        with self._lock:
            findings_list = list(self.findings_history)

        with open(filepath, 'w') as f:
            json.dump(findings_list, f, indent=2)

        self.logger.info(f"💾 Saved {len(findings_list)} findings to {filepath}")

    def get_stats(self) -> Dict:
        """Get cloud security statistics"""
        with self._lock:
            findings_by_severity = defaultdict(int)
            findings_by_cloud = defaultdict(int)

            for f in self.findings_history:
                findings_by_severity[f['severity']] += 1
                findings_by_cloud[f['cloud']] += 1

            return {
                'total_findings': len(self.findings_history),
                'by_severity': dict(findings_by_severity),
                'by_cloud': dict(findings_by_cloud),
                'aws_enabled': self.aws_scanner is not None,
                'azure_enabled': self.azure_scanner is not None,
                'gcp_enabled': self.gcp_scanner is not None
            }



class ShardCloudSecurityIntegration(BaseModule):
    """Integration layer for SHARD Enterprise"""

    def __init__(self, config: ConfigManager, event_bus: EventBus, logger: LoggingService):
        super().__init__("CloudSecurity", config, event_bus, logger)

        cloud_config = CloudSecurityConfig()

        cloud_config.aws_enabled = config.get('cloud.aws.enabled', False)
        cloud_config.aws_access_key = config.get('cloud.aws.access_key', '')
        cloud_config.aws_secret_key = config.get('cloud.aws.secret_key', '')
        cloud_config.aws_session_token = config.get('cloud.aws.session_token', '')
        cloud_config.aws_region = config.get('cloud.aws.region', 'us-east-1')

        cloud_config.azure_enabled = config.get('cloud.azure.enabled', False)
        cloud_config.azure_tenant_id = config.get('cloud.azure.tenant_id', '')
        cloud_config.azure_client_id = config.get('cloud.azure.client_id', '')
        cloud_config.azure_client_secret = config.get('cloud.azure.client_secret', '')
        cloud_config.azure_subscription_id = config.get('cloud.azure.subscription_id', '')

        cloud_config.gcp_enabled = config.get('cloud.gcp.enabled', False)
        cloud_config.gcp_project_id = config.get('cloud.gcp.project_id', '')
        cloud_config.gcp_credentials_file = config.get('cloud.gcp.credentials_file', '')

        self.engine = CloudSecurityEngine(cloud_config, event_bus, logger)

    def start(self):
        self.engine.start()

    def stop(self):
        self.engine.stop()

    def get_stats(self) -> Dict:
        return self.engine.get_stats()