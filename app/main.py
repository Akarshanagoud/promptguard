from fastapi import FastAPI

from app.models import ScanRequest, ScanResponse
from app.scanner import scan


app = FastAPI(
    title="PromptGuard",
    description="Prompt injection firewall middleware for AI agents.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
def scan_content(request: ScanRequest) -> ScanResponse:
    result = scan(request.content)
    return ScanResponse(**result)
