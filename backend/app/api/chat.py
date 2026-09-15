import json
from typing import List
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db, SessionLocal
from app.models.db_models import ChatMessageModel
from app.models.schemas import ChatRequest, ChatMessage
from app.services.ai_agent import AIAgentService

router = APIRouter(prefix="/api/chat", tags=["AI Copilot"])

@router.get("/history/{analysis_id}", response_model=List[ChatMessage])
def get_chat_history(analysis_id: str, db: Session = Depends(get_db)):
    """
    Retrieves stored chat messages for a specific network analysis session.
    """
    messages = db.query(ChatMessageModel).filter(
        ChatMessageModel.capture_id == analysis_id
    ).order_by(ChatMessageModel.created_at.asc()).all()

    return [ChatMessage(role=m.role, content=m.content) for m in messages]

@router.post("/stream")
async def chat_stream(request: ChatRequest):
    """
    Server-Sent Events (SSE) streaming endpoint for AI Network Copilot with database persistence.
    """
    collected_tokens = []

    async def event_generator():
        try:
            async for token in AIAgentService.stream_chat(request.messages, request.analysis_id):
                collected_tokens.append(token)
                payload = json.dumps({"token": token})
                yield f"data: {payload}\n\n"

            # Persist user query and assistant response to database on completion
            if request.analysis_id and request.messages:
                last_user_msg = request.messages[-1]
                full_reply = "".join(collected_tokens)
                db = SessionLocal()
                try:
                    db.add(ChatMessageModel(
                        capture_id=request.analysis_id,
                        role="user",
                        content=last_user_msg.content
                    ))
                    if full_reply:
                        db.add(ChatMessageModel(
                            capture_id=request.analysis_id,
                            role="assistant",
                            content=full_reply
                        ))
                    db.commit()
                except Exception as e:
                    db.rollback()
                    print(f"Warning: Failed to persist chat message: {e}")
                finally:
                    db.close()

        except Exception as e:
            err_payload = json.dumps({"error": str(e)})
            yield f"data: {err_payload}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )
