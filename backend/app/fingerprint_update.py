import json
import os

import requests

# enthec/webappanalyzer is the community-maintained fork of Wappalyzer's
# open dataset (the original project's data went closed/commercial). It
# shards technologies.json by first letter for its own tooling; we fetch
# every shard and merge into one dict so runtime only ever does one
# json.load() of one committed file -- no sharding logic in the hot path.
RAW_BASE_URL = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src"
SHARD_LETTERS = "abcdefghijklmnopqrstuvwxyz_"
REQUEST_TIMEOUT = 30

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
TECHNOLOGIES_PATH = os.path.join(DATA_DIR, "technologies.json")
CATEGORIES_PATH = os.path.join(DATA_DIR, "categories.json")


def fetch_latest_dataset() -> tuple[dict, dict]:
    """Fetches every technologies/{letter}.json shard plus categories.json
    from the enthec/webappanalyzer GitHub repo and merges the shards into
    one technologies dict. Raises requests.RequestException on any
    network failure -- the caller must leave the existing vendored files
    untouched on failure, never a partial overwrite."""
    technologies: dict = {}
    for letter in SHARD_LETTERS:
        response = requests.get(
            f"{RAW_BASE_URL}/technologies/{letter}.json", timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()
        technologies.update(response.json())

    categories_response = requests.get(f"{RAW_BASE_URL}/categories.json", timeout=REQUEST_TIMEOUT)
    categories_response.raise_for_status()
    categories = categories_response.json()

    return technologies, categories


def update_vendored_data() -> tuple[int, int]:
    """Fetches the latest dataset and overwrites the vendored JSON files.
    Both fetches (via fetch_latest_dataset) must succeed before anything
    on disk is touched -- a network failure partway through raises and
    leaves the existing vendored files exactly as they were."""
    technologies, categories = fetch_latest_dataset()

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(TECHNOLOGIES_PATH, "w", encoding="utf-8") as f:
        json.dump(technologies, f)
    with open(CATEGORIES_PATH, "w", encoding="utf-8") as f:
        json.dump(categories, f)

    return len(technologies), len(categories)
