"""VulnFetch — fetch and display recent HIGH/CRITICAL CVEs from the NVD API."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import requests
from requests.exceptions import (
    ConnectionError as RequestsConnectionError,
    HTTPError,
    RequestException,
    Timeout,
)
from rich.console import Console
from rich.table import Table
from rich.text import Text

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30
DEFAULT_LOOKBACK_DAYS = 7
DEFAULT_RESULTS_PER_PAGE = 100
MIN_SEVERITY_SCORE = 7.0
DESCRIPTION_MAX_LEN = 60

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "green",
    "NONE": "dim",
}

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="vulnfetch",
        description="Fetch recent HIGH/CRITICAL CVEs from the NVD API.",
    )
    parser.add_argument(
        "-d",
        "--days",
        type=int,
        default=DEFAULT_LOOKBACK_DAYS,
        help=f"Lookback window in days (default: {DEFAULT_LOOKBACK_DAYS}, max: 120).",
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=25,
        help="Maximum number of vulnerabilities to display (default: 25).",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Optional NVD API key (raises rate limit from 5 to 50 req/30s).",
    )
    return parser.parse_args()


def build_nvd_params(days: int, results_per_page: int) -> dict[str, Any]:
    if days < 1:
        days = 1
    if days > 120:
        days = 120

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    iso = "%Y-%m-%dT%H:%M:%S.000"
    return {
        "lastModStartDate": start.strftime(iso),
        "lastModEndDate": now.strftime(iso),
        "resultsPerPage": results_per_page,
    }


def fetch_cves(params: dict[str, Any], api_key: str | None) -> dict[str, Any]:
    headers = {"User-Agent": "VulnFetch/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    response = requests.get(
        NVD_API_URL,
        params=params,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )

    if response.status_code == 403:
        raise PermissionError(
            "NVD API returned 403 (forbidden). You may be rate-limited — "
            "wait a moment or pass --api-key to raise the limit."
        )
    if response.status_code == 429:
        raise PermissionError(
            "NVD API returned 429 (rate-limited). Slow down requests or pass --api-key."
        )

    response.raise_for_status()
    return response.json()


def extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    """Return the best available CVSS base score and severity from a CVE's metrics block.

    Prefers v3.1 → v3.0 → v2 in that order.
    """
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity")
            if score is not None:
                return float(score), severity

    entries = metrics.get("cvssMetricV2") or []
    if entries:
        first = entries[0]
        data = first.get("cvssData", {})
        score = data.get("baseScore")
        severity = first.get("baseSeverity") or data.get("baseSeverity")
        if score is not None:
            return float(score), severity

    return None, None


def pick_english_description(descriptions: list[dict[str, Any]]) -> str:
    for entry in descriptions:
        if entry.get("lang") == "en":
            return entry.get("value", "")
    if descriptions:
        return descriptions[0].get("value", "")
    return ""


def truncate(text: str, max_len: int) -> str:
    text = " ".join(text.split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


def filter_and_sort(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        metrics = cve.get("metrics", {})
        score, severity = extract_cvss(metrics)
        if score is None or score < MIN_SEVERITY_SCORE:
            continue

        normalized = (severity or "").upper()
        if normalized not in ("HIGH", "CRITICAL"):
            normalized = "CRITICAL" if score >= 9.0 else "HIGH"

        description = pick_english_description(cve.get("descriptions", []))
        rows.append(
            {
                "id": cve_id,
                "score": score,
                "severity": normalized,
                "description": description,
            }
        )

    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows


def render_table(rows: list[dict[str, Any]], window_days: int) -> Table:
    title = (
        f"VulnFetch — HIGH/CRITICAL CVEs (last {window_days} day"
        f"{'s' if window_days != 1 else ''})"
    )
    table = Table(
        title=title,
        title_style="bold cyan",
        header_style="bold white on blue",
        show_lines=False,
        expand=False,
    )
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("CVSS Score", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column(f"Description (max {DESCRIPTION_MAX_LEN} chars)", overflow="fold")

    for row in rows:
        severity = row["severity"]
        color = SEVERITY_COLORS.get(severity, "white")
        score_text = Text(f"{row['score']:.1f}", style=color)
        severity_text = Text(severity, style=color)
        description = truncate(row["description"], DESCRIPTION_MAX_LEN)
        table.add_row(row["id"], score_text, severity_text, description)

    return table


def main() -> int:
    args = parse_args()

    params = build_nvd_params(args.days, DEFAULT_RESULTS_PER_PAGE)

    with console.status("[cyan]Querying NVD API…", spinner="dots"):
        try:
            payload = fetch_cves(params, args.api_key)
        except Timeout:
            console.print(
                "[bold red]Error:[/bold red] The NVD API request timed out. "
                "Try again or increase the timeout."
            )
            return 2
        except RequestsConnectionError:
            console.print(
                "[bold red]Error:[/bold red] Could not reach the NVD API — "
                "check your network connection."
            )
            return 2
        except PermissionError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            return 3
        except HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "?"
            console.print(
                f"[bold red]Error:[/bold red] NVD API returned HTTP {status}."
            )
            return 4
        except RequestException as exc:
            console.print(f"[bold red]Network error:[/bold red] {exc}")
            return 5
        except ValueError:
            console.print(
                "[bold red]Error:[/bold red] NVD API returned a malformed JSON response."
            )
            return 6

    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        console.print("[yellow]No vulnerabilities returned by the API for this window.[/yellow]")
        return 0

    rows = filter_and_sort(vulnerabilities)
    if not rows:
        console.print(
            "[yellow]No HIGH or CRITICAL vulnerabilities found in the selected window.[/yellow]"
        )
        return 0

    rows = rows[: args.limit]

    table = render_table(rows, args.days)
    console.print(table)

    critical = sum(1 for r in rows if r["severity"] == "CRITICAL")
    high = sum(1 for r in rows if r["severity"] == "HIGH")
    console.print(
        f"\n[bold]Showing {len(rows)}[/bold] result(s) — "
        f"[bold red]{critical} CRITICAL[/bold red], "
        f"[orange1]{high} HIGH[/orange1] "
        f"(filtered from {len(vulnerabilities)} total)."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Aborted by user.[/yellow]")
        sys.exit(130)
