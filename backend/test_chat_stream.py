import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from app.models.schemas import ChatMessage
from app.services.ai_agent import AIAgentService
from app.services.dpi_runner import DPIRunnerService
from app.config import SAMPLE_PCAP_PATH

async def _test_chat():
    print("Testing AI Copilot Streaming...")
    # Initialize sample context
    DPIRunnerService.run_engine(input_pcap=SAMPLE_PCAP_PATH, custom_id="test_stream")
    
    messages = [ChatMessage(role="user", content="What domains were detected in this packet capture?")]
    tokens = []
    async for token in AIAgentService.stream_chat(messages, analysis_id="test_stream"):
        tokens.append(token)
        sys.stdout.write(token)
        sys.stdout.flush()
    print("\n\n[SUCCESS] AI Streaming Completed. Total chunks received:", len(tokens))
    assert len(tokens) > 0

def test_chat():
    asyncio.run(_test_chat())

if __name__ == "__main__":
    test_chat()
