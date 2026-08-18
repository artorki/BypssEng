# tests/test_dns.py
import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from diagnosis.dns import test_dns_layer
from engine.models import DiagnosisResult

@pytest.mark.asyncio
async def test_dns_hijack_detection():
    # شبیه‌سازی اینترفیس getaddrinfo که یک IP عمومی برای دامنه تصادفی برمی‌گرداند (نشانه Hijack)
    mock_getaddrinfo = AsyncMock(return_value=[
        (0, 0, 0, 0, ('185.199.108.133', 0)) # بازگشت IP نامعتبر برای دامنه رندم
    ])
    
    with patch('asyncio.get_running_loop', return_value=AsyncMock(getaddrinfo=mock_getaddrinfo)):
        # شبیه‌سازی موفقیت در DoH
        with patch('diagnosis.dns.test_doh_resolution', AsyncMock(return_value='ok')):
            result = await test_dns_layer()
            
    assert isinstance(result, DiagnosisResult)
    assert result.condition == "dns_hijacked"
    assert result.confidence >= 0.9
    assert "public_ip_returned_for_random_domain" in result.evidence