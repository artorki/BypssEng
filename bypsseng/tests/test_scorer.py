import pytest
from unittest.mock import AsyncMock
from decision.scorer import score_strategy
from bypsseng.domain.models import StrategyScore


@pytest.mark.asyncio
async def test_scoring_no_history():
    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 0.0

    mock_stats = AsyncMock()
    mock_stats.get_strategy_posterior.return_value = 0.5
    mock_stats.get_confidence.return_value = 0.1

    states = {"udp": "udp_ok", "dpi": "dpi_none", "speed": "speed_ok"}
    score = await score_strategy("vless", states, mock_db, mock_stats)

    assert isinstance(score, StrategyScore)
    assert score.strategy == "vless"
    assert any("No historical data" in reason for reason in score.reasons)

    assert score.score < 0.5


@pytest.mark.asyncio
async def test_scoring_high_history():
    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 0.9

    mock_stats = AsyncMock()
    mock_stats.get_strategy_posterior.return_value = 0.8
    mock_stats.get_confidence.return_value = 0.8

    states = {"udp": "udp_ok", "dpi": "dpi_none", "speed": "speed_ok"}
    score = await score_strategy("vless", states, mock_db, mock_stats)

    assert any("High historical success" in reason for reason in score.reasons)

    assert score.score > 0.5


@pytest.mark.asyncio
async def test_scoring_udp_blocked():

    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 0.5

    mock_stats = AsyncMock()
    mock_stats.get_strategy_posterior.return_value = 0.5
    mock_stats.get_confidence.return_value = 0.5

    states = {"udp": "udp_dropped", "dpi": "dpi_none", "speed": "speed_ok"}
    score = await score_strategy("hysteria2", states, mock_db, mock_stats)

    assert score.score == 0.0
    assert any("UDP blocked, TCP unsupported" in reason for reason in score.reasons)


@pytest.mark.asyncio
async def test_scoring_dpi_aggressive():
    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 0.5

    mock_stats = AsyncMock()
    mock_stats.get_strategy_posterior.return_value = 0.5
    mock_stats.get_confidence.return_value = 0.5

    states = {"udp": "udp_ok", "dpi": "dpi_aggressive", "speed": "speed_ok"}

    score_trojan = await score_strategy("trojan", states, mock_db, mock_stats)

    score_snowflake = await score_strategy("tor_snowflake", states, mock_db, mock_stats)

    assert score_snowflake.score > score_trojan.score
    assert any("High DPI resistance" in reason for reason in score_snowflake.reasons)
    assert any("Low DPI resistance" in reason for reason in score_trojan.reasons)


@pytest.mark.asyncio
async def test_scoring_safety_rails():
    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 1.0

    mock_stats = AsyncMock()

    mock_stats.get_strategy_posterior.return_value = 0.7
    mock_stats.get_confidence.return_value = 0.4

    states = {"udp": "udp_ok", "dpi": "dpi_none", "speed": "speed_ok"}
    score = await score_strategy("vless", states, mock_db, mock_stats)

    assert score.score < 1.0
