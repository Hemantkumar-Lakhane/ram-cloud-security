"""
CloudTrail Event Parser and Normalizer.
Transforms raw AWS CloudTrail JSON structures into validated NormalizedEvent instances.
"""

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional
from uuid import uuid4

from src.common.constants import TelemetrySource
from src.common.logger import get_logger
from src.common.models import NormalizedEvent
from src.preprocessing.base import BaseEventParser

logger = get_logger(__name__)


class CloudTrailParser(BaseEventParser):
    """
    Concrete parser for AWS CloudTrail event payloads.
    """

    # Keys to sanitize from raw payload storage to prevent credential leakage
    SENSITIVE_KEYS = {
        "password",
        "secretaccesskey",
        "sessiontoken",
        "token",
        "privatekey",
        "secret",
        "accesskey",
    }

    def parse(self, raw_data: Dict[str, Any]) -> NormalizedEvent:
        """
        Parses and validates a single raw CloudTrail JSON event into a NormalizedEvent.
        """
        if not isinstance(raw_data, dict):
            raise ValueError(f"Expected dict for CloudTrail event, received: {type(raw_data).__name__}")

        # 1. Parse Event Identification & Timing
        event_id = str(raw_data.get("eventID") or uuid4())
        timestamp = self._parse_timestamp(raw_data.get("eventTime"))

        # 2. Service & Action Details
        event_name = raw_data.get("eventName") or "UnknownEvent"
        event_source = raw_data.get("eventSource") or "unknown.amazonaws.com"
        region = raw_data.get("awsRegion")

        # 3. Identity Extraction
        user_identity = raw_data.get("userIdentity") or {}
        actor_arn = user_identity.get("arn")
        actor_name = user_identity.get("userName") or user_identity.get("principalId")
        actor_type = user_identity.get("type")

        # Session Issuer Extraction (e.g. for AssumedRole)
        session_context = user_identity.get("sessionContext") or {}
        session_issuer = session_context.get("sessionIssuer") or {}
        session_issuer_arn = session_issuer.get("arn")

        if not actor_name and session_issuer.get("userName"):
            actor_name = session_issuer.get("userName")

        # Account Context
        account_id = (
            raw_data.get("recipientAccountId")
            or user_identity.get("accountId")
            or session_issuer.get("accountId")
        )

        # 4. Network Context
        source_ip = raw_data.get("sourceIPAddress")
        user_agent = raw_data.get("userAgent")

        # 5. Outcome & Error Details
        error_code = raw_data.get("errorCode")
        error_message = raw_data.get("errorMessage")
        
        status_code = None
        response_elements = raw_data.get("responseElements")
        if isinstance(response_elements, dict):
            if "ConsoleLogin" in response_elements:
                status_code = response_elements["ConsoleLogin"]

        # 6. Resource Identifiers
        resources: List[Dict[str, Any]] = []
        raw_resources = raw_data.get("resources")
        if isinstance(raw_resources, list):
            for res in raw_resources:
                if isinstance(res, dict):
                    resources.append(
                        {
                            "arn": res.get("ARN"),
                            "type": res.get("type"),
                            "account_id": res.get("accountId"),
                        }
                    )

        # 7. Sanitized Raw Payload
        sanitized_payload = self._sanitize_payload(raw_data)

        return NormalizedEvent(
            event_id=event_id,
            timestamp=timestamp,
            source=TelemetrySource.CLOUDTRAIL,
            event_name=event_name,
            event_source=event_source,
            account_id=account_id,
            region=region,
            actor_arn=actor_arn,
            actor_name=actor_name,
            actor_type=actor_type,
            session_issuer_arn=session_issuer_arn,
            source_ip=source_ip,
            user_agent=user_agent,
            status_code=status_code,
            error_code=error_code,
            error_message=error_message,
            resources=resources,
            raw_payload=sanitized_payload,
        )

    def _parse_timestamp(self, time_val: Any) -> datetime:
        """
        Parses diverse ISO 8601 string timestamps into a UTC datetime.
        """
        if isinstance(time_val, datetime):
            if time_val.tzinfo is None:
                return time_val.replace(tzinfo=timezone.utc)
            return time_val.astimezone(timezone.utc)

        if isinstance(time_val, str):
            clean_str = time_val.strip()
            # Normalize trailing Z to +00:00 for ISO parsing
            if clean_str.endswith("Z"):
                clean_str = clean_str[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(clean_str)
                if dt.tzinfo is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                logger.warning(f"Could not parse timestamp string: '{time_val}'. Falling back to current UTC.")
                return datetime.now(timezone.utc)

        return datetime.now(timezone.utc)

    def _sanitize_payload(self, data: Any) -> Any:
        """
        Recursively masks sensitive tokens/passwords to ensure no credential leakage.
        """
        if isinstance(data, dict):
            sanitized = {}
            for k, v in data.items():
                if any(sens in k.lower() for sens in self.SENSITIVE_KEYS):
                    sanitized[k] = "[REDACTED]"
                else:
                    sanitized[k] = self._sanitize_payload(v)
            return sanitized
        elif isinstance(data, list):
            return [self._sanitize_payload(item) for item in data]
        return data
