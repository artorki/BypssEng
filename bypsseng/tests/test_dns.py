


import pytest
import asyncio
import socket
from unittest.mock import patch, AsyncMock
from diagnosis.dns import test_dns_layer
from bypsseng.domain.models import DiagnosisResult
from bypsseng.domain.conditions import NetworkCondition

@pytest.mark.asyncio
async def test_dns_hijack_detection():
    """
    Test DNS Hijack detection.
    Simulates a public IP returned for a random domain.
    """

    mock_getaddrinfo = AsyncMock(return_value=[
        (0, 0, 0, 0, ('185.199.108.133', 0)) # Public IP returned for random domain
    ])
    
    with patch('asyncio.get_running_loop', return_value=AsyncMock(getaddrinfo=mock_getaddrinfo)):

        with patch('diagnosis.dns.test_doh_resolution', AsyncMock(return_value='ok')):
            result = await test_dns_layer()
            
    assert isinstance(result, DiagnosisResult)

    assert result.condition == NetworkCondition.DNS_HIJACKED.value
    assert result.confidence >= 0.9
    assert "public_ip_returned_for_random_domain" in result.evidence

@pytest.mark.asyncio
async def test_dns_dropped():
    """
    Test DNS Dropped detection.
    Simulates UDP DNS queries and DoH both failing.
    """

    with patch('diagnosis.dns.send_dns_query', AsyncMock(return_value=None)):

        with patch('diagnosis.dns.test_doh_resolution', AsyncMock(return_value='dropped')):

            with patch('asyncio.get_running_loop', return_value=AsyncMock(getaddrinfo=AsyncMock(side_effect=Exception("DNS resolution failed")))):
                result = await test_dns_layer()
                
    assert isinstance(result, DiagnosisResult)
    assert result.condition == NetworkCondition.DNS_DROPPED.value
    assert result.confidence >= 0.9
    assert "udp_dropped" in result.evidence
    assert "doh_dropped" in result.evidence

@pytest.mark.asyncio
async def test_dns_ok():
    """
    Test DNS OK state.
    Simulates all DNS resolution methods working perfectly.
    """

    mock_getaddrinfo = AsyncMock(return_value=[
        (0, 0, 0, 0, ('8.8.8.8', 0))
    ])
    

    mock_udp_response = {'rcode': 0, 'ancount': 1, 'txid': 123, 'expected_txid': 123, 'latency': 45.2}
    
    with patch('asyncio.get_running_loop', return_value=AsyncMock(getaddrinfo=mock_getaddrinfo)):
        with patch('diagnosis.dns.send_dns_query', AsyncMock(return_value=mock_udp_response)):
            with patch('diagnosis.dns.test_doh_resolution', AsyncMock(return_value='ok')):

                with patch('asyncio.get_running_loop', return_value=AsyncMock(getaddrinfo=AsyncMock(side_effect=socket.gaierror))):
                    result = await test_dns_layer()
                    
    assert isinstance(result, DiagnosisResult)
    assert result.condition == NetworkCondition.DNS_OK.value
    assert result.confidence == 1.0

@pytest.mark.asyncio
async def test_dns_unknown_anomaly():
    """
    Section 27: Test Unknown Anomaly detection.
    Simulates conflicting observations (UDP unknown, DoH unknown).
    """

    mock_udp_response = {'rcode': 1, 'ancount': 0, 'txid': 123, 'expected_txid': 123, 'latency': 50.0}
    
    with patch('asyncio.get_running_loop', return_value=AsyncMock(getaddrinfo=AsyncMock(return_value=[(0,0,0,0,('8.8.8.8',0))]))):
        with patch('diagnosis.dns.send_dns_query', AsyncMock(return_value=mock_udp_response)):
            with patch('diagnosis.dns.test_doh_resolution', AsyncMock(return_value='unknown')):

                with patch('asyncio.get_running_loop', return_value=AsyncMock(getaddrinfo=AsyncMock(side_effect=socket.gaierror))):
                    result = await test_dns_layer()
                    
    assert isinstance(result, DiagnosisResult)

    assert result.condition == NetworkCondition.DNS_UNKNOWN.value
    assert result.confidence == 0.5
    assert "conflicting_observations" in result.evidence