from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from morphiq.models import FilterResult
from morphiq.pipeline.anomaly_detector import AnomalyDetector
from morphiq.pipeline.heuristic_filter import HeuristicFilter
from morphiq.pipeline.probe_detector import ProbeDetector


def test_heuristic_filter_matches_configured_rule(config_factory, store, log_entry):
    config = config_factory(
        heuristic_patterns=[
            {
                "name": "Admin path",
                "field": "path",
                "pattern": r"/admin",
                "description": "test rule",
            }
        ]
    )
    detector = HeuristicFilter(config, asyncio.Queue(), store)

    assert detector.evaluate(replace(log_entry, path="/admin")) is FilterResult.SUSPICIOUS
    assert detector.evaluate(replace(log_entry, path="/health")) is FilterResult.BENIGN


def test_probe_detector_tracks_distinct_paths(config_factory, store, log_entry):
    config = config_factory(probe_threshold=2)
    detector = ProbeDetector(config, store, asyncio.Queue(), asyncio.Queue())

    assert detector.check_probe(replace(log_entry, path="/one")) is False
    assert detector.check_probe(replace(log_entry, path="/two")) is False
    assert detector.check_probe(replace(log_entry, path="/three")) is True


@pytest.mark.asyncio
async def test_anomaly_detector_retrains_and_persists_model(
    config_factory, store, log_entry
):
    config = config_factory(min_training_samples=2)
    store.insert_traffic(log_entry, retention_s=3600)
    store.insert_traffic(replace(log_entry, path="/different"), retention_s=3600)
    detector = AnomalyDetector(config, asyncio.Queue(), store)

    sample_count = await detector.retrain()

    assert sample_count == 2
    assert detector._model is not None
    assert detector._heuristic_only_mode is False
