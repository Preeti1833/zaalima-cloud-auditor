"""Secure credential handling for AWS and GCP.

AWS: supports named local profiles (~/.aws/credentials) and optional role
assumption via STS, so the tool never needs long-lived keys pasted into
config files.

GCP: relies on Application Default Credentials (ADC) — i.e. whatever the
user has set up via `gcloud auth application-default login` or a service
account key referenced by GOOGLE_APPLICATION_CREDENTIALS — and never reads
or stores key material itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound


class AuthError(RuntimeError):
    """Raised when the tool cannot establish authenticated cloud access."""


@dataclass
class AWSContext:
    session: boto3.Session
    account_id: str
    profile: Optional[str]
    assumed_role_arn: Optional[str]


def get_aws_session(
    profile: Optional[str] = None,
    assume_role_arn: Optional[str] = None,
    region: Optional[str] = None,
    session_name: str = "cloud-auditor-session",
) -> AWSContext:
    """Build an authenticated boto3 session.

    Resolution order:
    1. If `assume_role_arn` is given, use the (optionally profile-scoped)
       base credentials to call sts:AssumeRole and build a session from the
       temporary credentials returned.
    2. Otherwise, use the named local profile directly.
    3. Otherwise, fall back to the default credential chain (env vars,
       instance/task role, etc).
    """
    try:
        base_session = boto3.Session(profile_name=profile, region_name=region)
    except ProfileNotFound as exc:
        raise AuthError(f"AWS profile '{profile}' was not found locally.") from exc

    if assume_role_arn:
        sts = base_session.client("sts")
        try:
            resp = sts.assume_role(RoleArn=assume_role_arn, RoleSessionName=session_name)
        except (ClientError, BotoCoreError) as exc:
            raise AuthError(f"Failed to assume role {assume_role_arn}: {exc}") from exc

        creds = resp["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=region,
        )
    else:
        session = base_session

    try:
        identity = session.client("sts").get_caller_identity()
    except (ClientError, BotoCoreError) as exc:
        raise AuthError(
            "Could not authenticate with AWS. Check your profile, credentials, "
            f"or assume-role permissions. Details: {exc}"
        ) from exc

    return AWSContext(
        session=session,
        account_id=identity["Account"],
        profile=profile,
        assumed_role_arn=assume_role_arn,
    )


@dataclass
class GCPContext:
    project: str
    credentials: object  # google.auth.credentials.Credentials


def get_gcp_context(project: Optional[str] = None) -> GCPContext:
    """Resolve GCP Application Default Credentials and project ID.

    Requires the `google-auth` package and either:
      - `gcloud auth application-default login` having been run, or
      - GOOGLE_APPLICATION_CREDENTIALS pointing at a service account key.
    """
    try:
        import google.auth
        from google.auth.exceptions import DefaultCredentialsError
    except ImportError as exc:
        raise AuthError(
            "google-auth is not installed. Run: pip install google-auth "
            "google-cloud-compute google-cloud-monitoring"
        ) from exc

    try:
        credentials, discovered_project = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
    except DefaultCredentialsError as exc:
        raise AuthError(
            "No GCP Application Default Credentials found. Run "
            "'gcloud auth application-default login' or set "
            "GOOGLE_APPLICATION_CREDENTIALS."
        ) from exc

    resolved_project = project or discovered_project
    if not resolved_project:
        raise AuthError(
            "No GCP project specified and none could be inferred from ADC. "
            "Pass --project explicitly."
        )

    return GCPContext(project=resolved_project, credentials=credentials)
