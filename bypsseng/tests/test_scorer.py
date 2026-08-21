


import pytest
from unittest.mock import AsyncMock
from decision.scorer import score_strategy
from bypsseng.domain.models import StrategyScore

@pytest.mark.asyncio
async def test_scoring_no_history():
    """
    Test scoring when there is no historical data (Exploration phase).
    Section 24: Adaptive Statistics should return neutral 0.5 posterior.
    """
    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 0.0
    
    mock_stats = AsyncMock()
    mock_stats.get_strategy_posterior.return_value = 0.5  # Neutral
    mock_stats.get_confidence.return_value = 0.1           # Low confidence
    
    states = {'udp': 'udp_ok', 'dpi': 'dpi_none', 'speed': 'speed_ok'}
    score = await score_strategy('vless', states, mock_db, mock_stats)
    
    assert isinstance(score, StrategyScore)
    assert score.strategy == 'vless'
    assert any("No historical data" in reason for reason in score.reasons)

    assert score.score < 0.5

@pytest.mark.asyncio
async def test_scoring_high_history():
    """
    Test scoring when historical success rate is high.
    Section 24: Bayesian Smoothing should return high posterior.
    """
    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 0.9 
    
    mock_stats = AsyncMock()
    mock_stats.get_strategy_posterior.return_value = 0.8  # Smoothed
    mock_stats.get_confidence.return_value = 0.8          # High confidence
    
    states = {'udp': 'udp_ok', 'dpi': 'dpi_none', 'speed': 'speed_ok'}
    score = await score_strategy('vless', states, mock_db, mock_stats)
    
    assert any("High historical success" in reason for reason in score.reasons)

    assert score.score > 0.5

@pytest.mark.asyncio
async def test_scoring_udp_blocked():
    """
    Test scoring when UDP is blocked and strategy is UDP-only.
    (HANDOFF Sec 10: Capability matching)
    """
    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 0.5
    
    mock_stats = AsyncMock()
    mock_stats.get_strategy_posterior.return_value = 0.5
    mock_stats.get_confidence.return_value = 0.5
    

    states = {'udp': 'udp_dropped', 'dpi': 'dpi_none', 'speed': 'speed_ok'}
    score = await score_strategy('hysteria2', states, mock_db, mock_stats)
    


    assert score.score == 0.0
    assert any("UDP blocked, TCP unsupported" in reason for reason in score.reasons)

@pytest.mark.asyncio
async def test_scoring_dpi_aggressive():
    """
    Test scoring when DPI is aggressive (SNI Filtering).
    (HANDOFF Sec 10: DPI Resistance capability)
    """
    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 0.5
    
    mock_stats = AsyncMock()
    mock_stats.get_strategy_posterior.return_value = 0.5
    mock_stats.get_confidence.return_value = 0.5
    

    states = {'udp': 'udp_ok', 'dpi': 'dpi_aggressive', 'speed': 'speed_ok'}
    

    score_trojan = await score_strategy('trojan', states, mock_db, mock_stats)

    score_snowflake = await score_strategy('tor_snowflake', states, mock_db, mock_stats)
    

    assert score_snowflake.score > score_trojan.score
    assert any("High DPI resistance" in reason for reason in score_snowflake.reasons)
    assert any("Low DPI resistance" in reason for reason in score_trojan.reasons)

@pytest.mark.asyncio
async def test_scoring_safety_rails():
    """
    Section 62: Safety Rails to prevent low-sample overconfidence.
    Even if DB returns perfect 1.0, the AdaptiveStatistics should smooth it down.
    """
    mock_db = AsyncMock()
    mock_db.get_strategy_success_rate.return_value = 1.0  # Perfect raw score
    
    mock_stats = AsyncMock()

    mock_stats.get_strategy_posterior.return_value = 0.7  # Smoothed down
    mock_stats.get_confidence.return_value = 0.4          # Low confidence due to low samples
    
    states = {'udp': 'udp_ok', 'dpi': 'dpi_none', 'speed': 'speed_ok'}
    score = await score_strategy('vless', states, mock_db, mock_stats)
    

    assert score.score < 1.0