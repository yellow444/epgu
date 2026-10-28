"""Generate dated public Shields endpoints from GitHub's real 14-day traffic."""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPOSITORY = "yellow444/epgu"
OUTPUT = Path(__file__).resolve().parents[1] / "docs" / "metrics"


def fetch_metric(metric, token):
    request = Request(
        f"https://api.github.com/repos/{REPOSITORY}/traffic/{metric}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "epgu-repository-traffic",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urlopen(request, timeout=30) as response:
        result = json.load(response)
    for field in ("count", "uniques"):
        if type(result.get(field)) is not int or result[field] < 0:
            raise ValueError(f"Invalid {metric} {field}")
    if result["uniques"] > result["count"]:
        raise ValueError(f"Invalid {metric} unique count")
    days = result.get(metric)
    if not isinstance(days, list) or not days:
        raise ValueError(f"Missing dated {metric} data; preserving previous snapshot")
    timestamps = sorted(datetime.fromisoformat(day["timestamp"].replace("Z", "+00:00")) for day in days)
    return {
        "count": result["count"],
        "uniques": result["uniques"],
        "firstReturnedDayUtc": timestamps[0].date().isoformat(),
        "lastReturnedDayUtc": timestamps[-1].date().isoformat(),
    }


def main():
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Set GH_TOKEN with repository Administration: read; no token is saved.", file=sys.stderr)
        return 1
    try:
        metrics = {name: fetch_metric(name, token) for name in ("views", "clones")}
    except HTTPError as error:
        print(f"GitHub traffic HTTP {error.code}; existing snapshots unchanged.", file=sys.stderr)
        return 1
    except (URLError, ValueError, KeyError, TypeError, OSError):
        print("GitHub traffic unavailable or invalid; existing snapshots unchanged.", file=sys.stderr)
        return 1
    updated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    snapshot = {"repository": REPOSITORY, "updatedAtUtc": updated, "window": "GitHub rolling last 14 days, not lifetime totals", **metrics}
    artifacts = {"snapshot.json": snapshot}
    for name, metric in metrics.items():
        artifacts[f"{name}.json"] = {
            "schemaVersion": 1,
            "label": f"{name} / 14d @ {updated[:10]}",
            "message": str(metric["count"]),
            "color": "blue" if name == "views" else "blueviolet",
        }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, artifact in artifacts.items():
        temporary = OUTPUT / f".{name}.tmp"
        temporary.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(OUTPUT / name)
    print(f"Traffic snapshot updated: views={metrics['views']['count']}, clones={metrics['clones']['count']}; {updated}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
