"""Shared utilities: rate limiting, region discovery, and small helpers."""

from __future__ import annotations

import functools
import time
from typing import Callable, Iterable, List, TypeVar

from botocore.exceptions import ClientError

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Rate limiting / retry
# ---------------------------------------------------------------------------

THROTTLE_ERROR_CODES = {
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "ThrottlingException",
    "RateLimitExceeded",
}


def with_backoff(max_retries: int = 5, base_delay: float = 1.0) -> Callable:
    """Decorator that retries a boto3 call with exponential backoff when the
    cloud API throttles the request. This keeps scanners well-behaved when
    sweeping many regions/accounts in quick succession.
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> T:
            attempt = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except ClientError as exc:
                    error_code = exc.response.get("Error", {}).get("Code", "")
                    attempt += 1
                    if error_code not in THROTTLE_ERROR_CODES or attempt > max_retries:
                        raise
                    delay = base_delay * (2 ** (attempt - 1))
                    time.sleep(delay)

        return wrapper

    return decorator


def chunked(items: List[T], size: int) -> Iterable[List[T]]:
    """Yield successive chunks of `size` from `items`."""
    for i in range(0, len(items), size):
        yield items[i : i + size]


# ---------------------------------------------------------------------------
# AWS region discovery
# ---------------------------------------------------------------------------

def get_all_aws_regions(session, service_name: str = "ec2") -> List[str]:
    """Return every AWS region enabled for the account, using EC2's
    describe_regions rather than a hardcoded list so newly-opted-in regions
    are picked up automatically.
    """
    client = session.client(service_name)
    resp = client.describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in resp.get("Regions", []))


def parse_region_list(regions_arg: str | None, session) -> List[str]:
    """Turn a comma-separated --regions argument into a list of region
    strings. If nothing is supplied, discover all enabled regions.
    """
    if not regions_arg:
        return get_all_aws_regions(session)
    return [r.strip() for r in regions_arg.split(",") if r.strip()]


# ---------------------------------------------------------------------------
# Cost estimation (rough, illustrative — not a billing API replacement)
# ---------------------------------------------------------------------------

# Very rough monthly USD estimates used to size the "potential savings"
# column in reports. These are deliberately conservative placeholders;
# for exact figures wire up the AWS Pricing API / GCP Billing API.
EBS_GP3_PER_GB_MONTH = 0.08
EIP_IDLE_PER_HOUR = 0.005
HOURS_PER_MONTH = 730

EC2_ROUGH_HOURLY_BY_FAMILY = {
    "t3": 0.0416,
    "t3a": 0.0376,
    "m5": 0.192,
    "m6i": 0.192,
    "c5": 0.17,
    "r5": 0.252,
    "default": 0.10,
}


def estimate_ebs_monthly_cost(size_gb: int) -> float:
    return round(size_gb * EBS_GP3_PER_GB_MONTH, 2)


def estimate_eip_monthly_cost() -> float:
    return round(EIP_IDLE_PER_HOUR * HOURS_PER_MONTH, 2)


def estimate_ec2_monthly_cost(instance_type: str) -> float:
    family = instance_type.split(".")[0] if instance_type else "default"
    hourly = EC2_ROUGH_HOURLY_BY_FAMILY.get(family, EC2_ROUGH_HOURLY_BY_FAMILY["default"])
    return round(hourly * HOURS_PER_MONTH, 2)
