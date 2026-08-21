
import os, pytest
from aegis402.x402_adapter import X402FacilitatorAdapter

@pytest.mark.integration
def test_live_x402_facilitator_supported():
    url=os.getenv("AEGIS_FACILITATOR_URL")
    if not url or not os.getenv("AEGIS_LIVE_X402"): pytest.skip("live x402 integration not configured")
    adapter=X402FacilitatorAdapter(url,2)
    supported=adapter.supported()
    assert isinstance(supported,dict) and "kinds" in supported
