from enum import Enum

from pydantic import BaseModel, Field


class ContentSource(str, Enum):
    USER_PROMPT = "user_prompt"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED_DOCUMENT = "retrieved_document"
    AGENT_RESPONSE = "agent_response"


class ScanRequest(BaseModel):
    source: ContentSource = Field(
        default=ContentSource.USER_PROMPT,
        description="Where the scanned content came from.",
    )
    content: str = Field(min_length=1, description="Text to inspect before agent use.")


class ScanResponse(BaseModel):
    allowed: bool
    risk_score: int = Field(ge=0, le=100)
    risk_level: str
    categories: list[str]
    action: str
    sanitized_content: str
