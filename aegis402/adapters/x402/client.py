from __future__ import annotations
class AegisX402Client:
    """Thin security hook around the official x402 HTTP client.

    The caller supplies an already configured official x402ClientSync whose
    scheme signer is owned by an external wallet. Aegis402 never receives a
    private key and never implements payment signing itself.
    """
    def __init__(self, x402_client_sync):
        from x402.http import x402HTTPClientSync
        self.http=x402HTTPClientSync(x402_client_sync)
    def handle_402(self,headers:dict[str,str],body:bytes|None):
        return self.http.handle_402_response(headers,body)
