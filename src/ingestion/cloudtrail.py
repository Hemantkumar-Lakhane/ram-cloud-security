"""
AWS CloudTrail Ingestion Engine.
Supports local JSON, JSONL, gzip compressed files, directory scanning, and read-only AWS S3 log collection.
"""

import gzip
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from src.common.logger import get_logger
from src.common.models import NormalizedEvent
from src.ingestion.base import BaseTelemetryIngestion
from src.preprocessing.parser import CloudTrailParser

logger = get_logger(__name__)


class CloudTrailIngestion(BaseTelemetryIngestion):
    """
    Concrete ingestion collector for AWS CloudTrail telemetry.
    """

    def __init__(
        self,
        file_path: Optional[Union[str, Path]] = None,
        s3_bucket: Optional[str] = None,
        s3_prefix: Optional[str] = None,
        s3_client: Optional[Any] = None,
    ):
        """
        Initialize the CloudTrail ingestion collector.

        Args:
            file_path: Path to a local JSON, JSONL, or .gz file, or directory of files.
            s3_bucket: Name of S3 bucket for read-only collection.
            s3_prefix: S3 key prefix for CloudTrail logs.
            s3_client: Optional injected boto3 S3 client (for dependency injection/testing).
        """
        self.file_path = Path(file_path) if file_path else None
        self.s3_bucket = s3_bucket
        self.s3_prefix = s3_prefix or ""
        self._s3_client = s3_client
        self.parser = CloudTrailParser()

    def ingest(self) -> Iterator[Dict[str, Any]]:
        """
        Yields raw CloudTrail event dictionaries from configured local sources or S3.
        """
        if self.file_path:
            yield from self._ingest_local_path(self.file_path)
        elif self.s3_bucket:
            yield from self._ingest_s3_bucket(self.s3_bucket, self.s3_prefix)
        else:
            logger.warning("No file path or S3 bucket specified for CloudTrail ingestion.")

    def ingest_normalized(self) -> Iterator[NormalizedEvent]:
        """
        Convenience generator that parses and normalizes events on-the-fly.
        """
        for raw_event in self.ingest():
            try:
                yield self.parser.parse(raw_event)
            except Exception as e:
                logger.error(f"Failed to normalize raw event: {e}. Event summary: {str(raw_event)[:200]}")

    def _ingest_local_path(self, path: Path) -> Iterator[Dict[str, Any]]:
        """
        Ingests events from a single local file or recursively from a directory.
        """
        if not path.exists():
            raise FileNotFoundError(f"CloudTrail log path does not exist: {path}")

        if path.is_dir():
            for child in sorted(path.rglob("*")):
                if child.is_file() and (
                    child.suffix.lower() in [".json", ".jsonl", ".gz"]
                    or child.name.endswith(".json.gz")
                    or child.name.endswith(".jsonl.gz")
                ):
                    yield from self._ingest_single_file(child)
        else:
            yield from self._ingest_single_file(path)

    def _ingest_single_file(self, file_path: Path) -> Iterator[Dict[str, Any]]:
        """
        Reads and yields records from a local file (plain text or gzip, JSON or JSONL).
        """
        is_gzip = file_path.suffix.lower() == ".gz" or file_path.name.endswith(".gz")
        
        open_fn = gzip.open if is_gzip else open
        mode = "rt" if is_gzip else "r"

        try:
            with open_fn(file_path, mode=mode, encoding="utf-8") as f:
                # Check for line-delimited JSON format first
                if file_path.name.endswith(".jsonl") or file_path.name.endswith(".jsonl.gz"):
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            if isinstance(record, dict):
                                yield record
                        except json.JSONDecodeError as err:
                            logger.warning(f"Malformed JSONL at {file_path}:{line_num}: {err}")
                else:
                    # Standard JSON file: could be single object or {"Records": [...]} envelope
                    content = f.read().strip()
                    if not content:
                        return
                    try:
                        data = json.loads(content)
                        if isinstance(data, dict):
                            if "Records" in data and isinstance(data["Records"], list):
                                for rec in data["Records"]:
                                    if isinstance(rec, dict):
                                        yield rec
                            else:
                                yield data
                        elif isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    yield item
                    except json.JSONDecodeError:
                        # Fallback attempt for JSONL lines in .json file
                        f.seek(0)
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    rec = json.loads(line)
                                    if isinstance(rec, dict):
                                        yield rec
                                except json.JSONDecodeError:
                                    pass
        except Exception as e:
            logger.error(f"Error reading CloudTrail file {file_path}: {e}")
            raise

    def _ingest_s3_bucket(self, bucket: str, prefix: str) -> Iterator[Dict[str, Any]]:
        """
        Reads CloudTrail logs from an S3 bucket in read-only mode using pagination.
        """
        s3 = self._s3_client
        if s3 is None:
            try:
                import boto3
                s3 = boto3.client("s3")
            except Exception as e:
                logger.error(f"Failed to initialize boto3 S3 client: {e}")
                raise

        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            contents = page.get("Contents", [])
            for obj in contents:
                key = obj.get("Key", "")
                if key.endswith(".json") or key.endswith(".json.gz") or key.endswith(".jsonl"):
                    try:
                        response = s3.get_object(Bucket=bucket, Key=key)
                        body_stream = response["Body"]
                        
                        if key.endswith(".gz"):
                            with gzip.GzipFile(fileobj=body_stream) as gz_file:
                                content = gz_file.read().decode("utf-8")
                        else:
                            content = body_stream.read().decode("utf-8")

                        data = json.loads(content)
                        if isinstance(data, dict) and "Records" in data and isinstance(data["Records"], list):
                            for rec in data["Records"]:
                                yield rec
                        elif isinstance(data, dict):
                            yield data
                        elif isinstance(data, list):
                            for rec in data:
                                yield rec
                    except Exception as err:
                        logger.error(f"Error fetching/parsing s3://{bucket}/{key}: {err}")
