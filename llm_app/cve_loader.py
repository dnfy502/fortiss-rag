from __future__ import annotations

import json
import re
from pathlib import Path


def normalize_cve_id(cve_id: str) -> str:
    cve_id = cve_id.strip().upper()
    if cve_id.startswith("CVE-"):
        return cve_id
    if re.match(r"^\d{4}-\d{4,}$", cve_id):
        return f"CVE-{cve_id}"
    raise ValueError("Invalid CVE ID format. Use CVE-YYYY-NNNN.")


def _cve_record_path(cve_id: str) -> Path:
    match = re.match(r"^CVE-(\d{4})-(\d{4,})$", cve_id)
    if not match:
        raise ValueError("Invalid CVE ID format. Use CVE-YYYY-NNNN.")
    year, number = match.groups()
    prefix = number[: max(1, len(number) - 3)] + "xxx"
    return (
        Path(__file__).resolve().parents[1]
        / "data"
        / "cvelistV5-main"
        / "cves"
        / year
        / prefix
        / f"{cve_id}.json"
    )


def load_cve_record(cve_id: str) -> dict:
    record_path = _cve_record_path(cve_id)
    if not record_path.exists():
        raise FileNotFoundError(f"CVE record not found at {record_path}")
    return json.loads(record_path.read_text(encoding="utf-8"))


def _collect_descriptions(cna: dict) -> list[str]:
    descriptions = []
    for item in cna.get("descriptions", []):
        if item.get("lang") == "en" and item.get("value"):
            descriptions.append(item["value"])
    return descriptions


def _collect_affected(affected: list[dict]) -> list[str]:
    lines = []
    for entry in affected:
        vendor = entry.get("vendor", "n/a")
        product = entry.get("product", "n/a")
        versions = []
        for version in entry.get("versions", []):
            version_str = version.get("version")
            status = version.get("status")
            if version_str and status:
                versions.append(f"{version_str} ({status})")
            elif version_str:
                versions.append(version_str)
        version_text = "; ".join(versions) if versions else "n/a"
        lines.append(f"{vendor} / {product}: {version_text}")
    return lines


def _collect_references(containers: dict) -> list[str]:
    urls = []
    cna = containers.get("cna", {})
    for ref in cna.get("references", []):
        url = ref.get("url")
        if url:
            urls.append(url)
    for adp in containers.get("adp", []) or []:
        for ref in adp.get("references", []):
            url = ref.get("url")
            if url:
                urls.append(url)
    return urls


def _collect_metrics(containers: dict) -> list[str]:
    lines = []
    for adp in containers.get("adp", []) or []:
        for metric in adp.get("metrics", []) or []:
            cvss = metric.get("cvssV3_1")
            if not cvss:
                continue
            base = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")
            vector = cvss.get("vectorString")
            if base is not None or severity or vector:
                lines.append(f"CVSS v3.1: {base} {severity} {vector}".strip())
    return lines


def build_cve_prompt(cve_id: str, record: dict) -> str:
    metadata = record.get("cveMetadata", {})
    containers = record.get("containers", {})
    cna = containers.get("cna", {})

    lines = [f"CVE ID: {cve_id}"]
    if metadata:
        lines.append(f"State: {metadata.get('state', 'n/a')}")
        lines.append(f"Published: {metadata.get('datePublished', 'n/a')}")
        lines.append(f"Updated: {metadata.get('dateUpdated', 'n/a')}")

    descriptions = _collect_descriptions(cna)
    if descriptions:
        lines.append("Descriptions:")
        lines.extend(f"- {desc}" for desc in descriptions)

    affected = _collect_affected(cna.get("affected", []))
    if affected:
        lines.append("Affected:")
        lines.extend(f"- {line}" for line in affected)

    references = _collect_references(containers)
    if references:
        lines.append("References:")
        lines.extend(f"- {url}" for url in references)

    metrics = _collect_metrics(containers)
    if metrics:
        lines.append("Metrics:")
        lines.extend(f"- {metric}" for metric in metrics)

    lines.append(
        "Note: Do not infer the CWE from any linked CWE IDs; they are intentionally omitted."
    )
    return "\n".join(lines)
