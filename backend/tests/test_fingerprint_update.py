from unittest.mock import MagicMock, patch

import pytest
import requests

from app import fingerprint_update


def _mock_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    return response


def test_fetch_latest_dataset_merges_all_shards_and_categories():
    def fake_get(url, **kwargs):
        if url.endswith("/categories.json"):
            return _mock_response({"1": {"name": "CMS"}})
        letter = url.rsplit("/", 1)[-1].removesuffix(".json")
        return _mock_response({f"Tech{letter}": {"cats": [1]}})

    with patch("app.fingerprint_update.requests.get", side_effect=fake_get):
        technologies, categories = fingerprint_update.fetch_latest_dataset()

    assert len(technologies) == len(fingerprint_update.SHARD_LETTERS)
    assert "Techa" in technologies
    assert categories == {"1": {"name": "CMS"}}


def test_fetch_latest_dataset_raises_on_network_failure():
    with patch(
        "app.fingerprint_update.requests.get",
        side_effect=requests.RequestException("down"),
    ):
        with pytest.raises(requests.RequestException):
            fingerprint_update.fetch_latest_dataset()


def test_update_vendored_data_writes_both_files(tmp_path, monkeypatch):
    monkeypatch.setattr(fingerprint_update, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(fingerprint_update, "TECHNOLOGIES_PATH", str(tmp_path / "technologies.json"))
    monkeypatch.setattr(fingerprint_update, "CATEGORIES_PATH", str(tmp_path / "categories.json"))

    def fake_get(url, **kwargs):
        if url.endswith("/categories.json"):
            return _mock_response({"1": {"name": "CMS"}})
        return _mock_response({"nginx": {"cats": [1]}})

    with patch("app.fingerprint_update.requests.get", side_effect=fake_get):
        tech_count, cat_count = fingerprint_update.update_vendored_data()

    assert tech_count == 1
    assert cat_count == 1
    assert (tmp_path / "technologies.json").exists()
    assert (tmp_path / "categories.json").exists()


def test_update_vendored_data_leaves_existing_files_untouched_on_failure(tmp_path, monkeypatch):
    tech_path = tmp_path / "technologies.json"
    tech_path.write_text('{"existing": {}}')
    monkeypatch.setattr(fingerprint_update, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(fingerprint_update, "TECHNOLOGIES_PATH", str(tech_path))
    monkeypatch.setattr(fingerprint_update, "CATEGORIES_PATH", str(tmp_path / "categories.json"))

    with patch(
        "app.fingerprint_update.requests.get",
        side_effect=requests.RequestException("down"),
    ):
        with pytest.raises(requests.RequestException):
            fingerprint_update.update_vendored_data()

    assert tech_path.read_text() == '{"existing": {}}'
