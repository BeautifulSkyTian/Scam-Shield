from google import genai
from pydantic import ValidationError

from app.core.config import GEMINI_API_KEY
from app.schemas import AnalyzeRequest, AnalyzeResponse


client = genai.Client(api_key=GEMINI_API_KEY)


SYSTEM_PROMPT = """
You are a cybersecurity scam detection system.

Your job is to analyze messages for signs of scams, phishing,
social engineering, impersonation, fraud, or malicious intent.

Evaluate the message using all available information:
- message content
- claimed sender
- URLs
- urgency or pressure tactics
- requests for credentials or money
- impersonation
- suspicious promises or threats

Risk score:
0-20: Very likely safe
21-40: Low risk
41-60: Suspicious
61-80: High risk
81-100: Very high risk

Do not assume a message is malicious simply because it contains
words commonly found in scams.

Give concise and specific reasons based only on the evidence provided.
"""


class AIServiceError(Exception):
    pass


def analyze_scam(request: AnalyzeRequest) -> AnalyzeResponse:
    prompt = f"""
{SYSTEM_PROMPT}

Analyze the following message.

Message:
{request.message}

Sender:
{request.sender or "Unknown"}

URL:
{request.url or "None provided"}
"""

    try:
        response = client.interactions.create(
            model="gemini-3.6-flash",
            input=prompt,
            response_format={
                "type": "text",
                "mime_type": "application/json",
                "schema": AnalyzeResponse.model_json_schema(),
            },
        )

        output_text = response.output_text

        if not output_text:
            raise AIServiceError("Gemini returned an empty response")

        return AnalyzeResponse.model_validate_json(output_text)

    except ValidationError as error:
        raise AIServiceError("Gemini returned an invalid structured response") from error

    except AIServiceError:
        raise

    except Exception as error:
        raise AIServiceError("Failed to analyze message with Gemini") from error