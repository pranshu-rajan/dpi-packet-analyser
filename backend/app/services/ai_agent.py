import os
import json
import time
import asyncio
from typing import AsyncGenerator, List, Dict, Any, Optional

from app.config import GEMINI_API_KEY, OPENAI_API_KEY, GROQ_API_KEY, GROQ_MODEL, SAMPLE_PCAP_PATH
from app.models.schemas import ChatMessage
from app.services.dpi_runner import ANALYSIS_CACHE, DPIRunnerService

def build_system_context(analysis_data: Optional[Dict[str, Any]]) -> str:
    base_instructions = (
        "You are NetCopilot, an elite AI Network Security Analyst and Deep Packet Inspection (DPI) expert. "
        "You help network administrators and security engineers analyze PCAP files, investigate TLS SNI handshakes, "
        "detect cybersecurity threats, and configure firewall blocking rules.\n\n"
        "### MANDATORY RESPONSE SCHEMA:\n"
        "Structure your technical responses using this standard professional cybersecurity schema:\n\n"
        "#### 1. 📌 Executive Summary\n"
        "A clear 1-2 sentence direct answer summarizing the network finding.\n\n"
        "#### 2. 🔍 Telemetry & Evidence\n"
        "A structured Markdown table with exact data points from the capture (e.g. Domain / Host, Protocol, Port, App, Count, Status).\n\n"
        "#### 3. ⚠️ Risk & Security Assessment\n"
        "State the risk level (`LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`) and analyze protocol vulnerabilities or exposure.\n\n"
        "#### 4. 🛡️ Recommended Containment Actions\n"
        "Actionable mitigation steps. Whenever recommending to block an application, IP, or domain, output this special action tag on its own line:\n"
        "`[SUGGEST_RULE:app:AppName:Reason]` or `[SUGGEST_RULE:ip:1.2.3.4:Reason]` or `[SUGGEST_RULE:domain:domain.com:Reason]`\n"
    )

    if not analysis_data:
        return base_instructions + "\n(No active PCAP analysis currently loaded in context. Ask the user to upload or select a capture.)"

    resp = analysis_data.get("response", {})
    summary = resp.get("summary", {})
    apps = resp.get("applications", [])
    snis = resp.get("detected_snis", [])
    threats = resp.get("threat_indicators", [])
    rules = resp.get("active_rules", [])

    app_list_str = ', '.join([f"{a.get('name')}: {a.get('count')} ({a.get('percentage')}%)" for a in apps[:10]])
    sni_list_str = ', '.join([f"{s.get('sni')} ({s.get('app')})" for s in snis[:15]])
    threat_list_str = ', '.join([t.get('title', '') for t in threats]) or 'None'
    rules_list_str = ', '.join([f"{r.get('type')}:{r.get('value')}" for r in rules]) or 'None'

    context = (
        f"{base_instructions}\n"
        f"--- ACTIVE PCAP TELEMETRY CONTEXT ---\n"
        f"- File: {resp.get('filename')} ({resp.get('file_size_bytes', 0)} bytes)\n"
        f"- Total Packets: {summary.get('total_packets', 0)} (Forwarded: {summary.get('forwarded', 0)}, Dropped: {summary.get('dropped', 0)})\n"
        f"- TCP: {summary.get('tcp_packets', 0)}, UDP: {summary.get('udp_packets', 0)}\n"
        f"- Threat Risk Score: {resp.get('threat_score', 0)}/100\n"
        f"- Applications Detected: {app_list_str}\n"
        f"- Detected SNIs / Domains: {sni_list_str}\n"
        f"- Active Security Indicators: {threat_list_str}\n"
        f"- Active Firewall Rules: {rules_list_str}\n"
        f"--------------------------------------\n"
    )
    return context


class AIAgentService:
    @staticmethod
    async def stream_chat(
        messages: List[ChatMessage],
        analysis_id: Optional[str] = None
    ) -> AsyncGenerator[str, None]:
        analysis_data = ANALYSIS_CACHE.get(analysis_id) if analysis_id else None
        
        # Auto fallback to latest active capture if analysis_id not found
        if not analysis_data and ANALYSIS_CACHE:
            analysis_data = list(ANALYSIS_CACHE.values())[-1]
        elif not analysis_data and SAMPLE_PCAP_PATH.exists():
            try:
                DPIRunnerService.run_engine(SAMPLE_PCAP_PATH, custom_id="sample_live")
                analysis_data = ANALYSIS_CACHE.get("sample_live")
            except Exception:
                pass

        system_prompt = build_system_context(analysis_data)
        user_query = messages[-1].content if messages else "Hello"

        # 1. Check for Groq API Key (Ultra-fast 500+ tokens/sec LPU streaming)
        if GROQ_API_KEY:
            try:
                import httpx
                headers = {
                    "Authorization": f"Bearer {GROQ_API_KEY}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": GROQ_MODEL,
                    "messages": [{"role": "system", "content": system_prompt}] + [
                        {"role": m.role, "content": m.content} for m in messages
                    ],
                    "stream": True,
                    "temperature": 0.3
                }
                async with httpx.AsyncClient(timeout=30.0) as client:
                    async with client.stream(
                        "POST",
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers=headers,
                        json=payload
                    ) as resp:
                        if resp.status_code == 200:
                            async for line in resp.aiter_lines():
                                if line.startswith("data: "):
                                    data_str = line[6:].strip()
                                    if data_str == "[DONE]":
                                        break
                                    try:
                                        chunk_obj = json.loads(data_str)
                                        delta = chunk_obj["choices"][0].get("delta", {}).get("content", "")
                                        if delta:
                                            yield delta
                                    except Exception:
                                        continue
                            return
                        else:
                            err_body = await resp.aread()
                            yield f"[Notice: Groq HTTP {resp.status_code}. Switching to fallback engine...]\n\n"
            except Exception as e:
                yield f"[Notice: Groq error ({str(e)}). Switching to fallback engine...]\n\n"

        # 2. Check for Gemini API Key
        if GEMINI_API_KEY:
            try:
                import google.generativeai as genai
                genai.configure(api_key=GEMINI_API_KEY)
                model = genai.GenerativeModel(
                    model_name="gemini-1.5-flash",
                    system_instruction=system_prompt
                )
                
                # Format conversation history
                chat_history = []
                for msg in messages[:-1]:
                    role = "user" if msg.role == "user" else "model"
                    chat_history.append({"role": role, "parts": [msg.content]})

                chat = model.start_chat(history=chat_history)
                response = await asyncio.to_thread(chat.send_message, user_query, stream=True)

                for chunk in response:
                    if chunk.text:
                        yield chunk.text
                        await asyncio.sleep(0.01)
                return
            except Exception as e:
                # Log and fallback to offline engine
                yield f"[Notice: Gemini error ({str(e)}). Switching to NetCopilot Offline Intelligence Engine...]\n\n"

        # 2. Check for OpenAI API Key
        if OPENAI_API_KEY:
            try:
                import httpx
                headers = {
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "system", "content": system_prompt}] + [
                        {"role": m.role, "content": m.content} for m in messages
                    ],
                    "stream": True
                }
                async with httpx.AsyncClient(timeout=30.0) as client:
                    async with client.stream(
                        "POST",
                        "https://api.openai.com/v1/chat/completions",
                        headers=headers,
                        json=payload
                    ) as resp:
                        async for line in resp.aiter_lines():
                            if line.startswith("data: "):
                                data_str = line[6:].strip()
                                if data_str == "[DONE]":
                                    break
                                try:
                                    chunk_obj = json.loads(data_str)
                                    delta = chunk_obj["choices"][0].get("delta", {}).get("content", "")
                                    if delta:
                                        yield delta
                                except Exception:
                                    continue
                return
            except Exception as e:
                yield f"[Notice: OpenAI error ({str(e)}). Switching to NetCopilot Offline Intelligence Engine...]\n\n"

        # 3. Intelligent Offline Deterministic Security Intelligence Engine
        async for chunk in AIAgentService._offline_intelligence_stream(user_query, analysis_data):
            yield chunk

    @staticmethod
    async def _offline_intelligence_stream(
        query: str,
        analysis_data: Optional[Dict[str, Any]]
    ) -> AsyncGenerator[str, None]:
        """
        State-of-the-art offline cybersecurity analysis engine that parses user questions
        and generates context-grounded network diagnostics and recommendations with simulated SSE streaming.
        """
        q = query.lower()
        resp = analysis_data.get("response", {}) if analysis_data else {}
        summary = resp.get("summary", {})
        apps = resp.get("applications", [])
        snis = resp.get("detected_snis", [])
        threats = resp.get("threat_indicators", [])
        rules = resp.get("active_rules", [])

        # Build tailored technical responses
        if any(w in q for w in ["domain", "sni", "website", "visited", "urls"]):
            if snis:
                text = (
                    f"### 🌐 Detected TLS SNI & Domain Breakdown\n\n"
                    f"The Deep Packet Inspection engine parsed the TLS Client Hello handshakes and identified **{len(snis)} unique domains** in this capture:\n\n"
                )
                text += "| Detected Domain / SNI | Application Classification | Inspection Status |\n"
                text += "| :--- | :--- | :--- |\n"
                for s in snis:
                    text += f"| `{s.get('sni')}` | **{s.get('app')}** | ✅ Inspected |\n"
                text += (
                    f"\n**Security Analysis**: Because Server Name Indication (SNI) is transmitted in the TLS Client Hello "
                    f"before encryption keys are negotiated, our DPI engine extracts the target host without decrypting user payloads.\n\n"
                    f"To block any unwanted domain, you can apply a rule directly:\n"
                    f"`[SUGGEST_RULE:domain:{snis[0].get('sni', 'example.com')}:Targeted domain containment]`"
                )
            else:
                text = "No TLS SNI domains were detected in this session. The capture may consist purely of raw IP or UDP datagrams."

        elif any(w in q for w in ["threat", "risk", "security", "vulnerability", "malware", "alert"]):
            score = resp.get("threat_score", 15)
            text = (
                f"### 🛡️ Cybersecurity Risk Assessment\n\n"
                f"- **Calculated Threat Index**: **{score}/100**\n"
                f"- **Overall Risk Level**: `{'CRITICAL' if score > 70 else ('ELEVATED' if score > 35 else 'LOW')}`\n\n"
                f"#### Diagnostic Findings:\n"
            )
            if threats:
                for idx, t in enumerate(threats, 1):
                    text += (
                        f"{idx}. **{t.get('title')}** `[{t.get('severity').upper()}]`\n"
                        f"   - *Details*: {t.get('description')}\n"
                        f"   - *Remediation*: {t.get('suggested_action')}\n\n"
                    )
            else:
                text += "- ✅ No critical protocol violations detected in current traffic sample.\n\n"

            text += (
                "**Recommended Action Plan**:\n"
                "1. Enforce strict TLS 1.3 to mitigate plaintext fallback.\n"
                "2. Apply firewall rules on entertainment or high-bandwidth social applications.\n"
            )

        elif any(w in q for w in ["block", "rule", "firewall", "filter", "drop", "prevent"]):
            text = (
                f"### 🧱 Firewall Rule Recommendations\n\n"
                f"Based on the observed traffic distribution, here are suggested rules for policy enforcement:\n\n"
            )
            # Find candidate apps to suggest
            suggested = False
            for app in apps:
                if app.get("name") in ["YouTube", "TikTok", "Instagram", "Spotify", "Discord"]:
                    text += (
                        f"- **Block {app.get('name')}**: Currently consuming {app.get('percentage')}% of packets.\n"
                        f"  `[SUGGEST_RULE:app:{app.get('name')}:Bandwidth and policy management]`\n\n"
                    )
                    suggested = True
            if not suggested:
                text += (
                    "- **Block Specific Source IP**: Prevent unauthorized device chatter.\n"
                    "  `[SUGGEST_RULE:ip:192.168.1.50:Restricting unauthorized host]`\n\n"
                    "- **Block Streaming Domain**:\n"
                    "  `[SUGGEST_RULE:domain:youtube.com:Corporate policy restriction]`\n\n"
                )
            text += "Clicking any suggested rule in the UI will immediately arm the DPI engine and re-filter the PCAP."

        elif any(w in q for w in ["summary", "overview", "report", "stat", "packets"]):
            text = (
                f"### 📊 Capture Telemetry Summary\n\n"
                f"- **Input File**: `{resp.get('filename', 'N/A')}`\n"
                f"- **Total Captured Packets**: **{summary.get('total_packets', 0):,}**\n"
                f"- **Total Volume**: **{summary.get('total_bytes', 0):,} bytes**\n"
                f"- **Forwarded**: **{summary.get('forwarded', 0):,}** | **Dropped**: **{summary.get('dropped', 0):,}**\n"
                f"- **Protocols**: TCP ({summary.get('tcp_packets', 0)}) | UDP ({summary.get('udp_packets', 0)})\n\n"
                f"#### Top Application Signatures:\n"
            )
            for a in apps[:5]:
                text += f"- **{a.get('name')}**: {a.get('count')} packets ({a.get('percentage')}%\n"
            text += f"\nFiltered PCAP is ready for download in the top action bar."

        elif any(w in q for w in ["how", "explain", "tls", "handshake", "sni", "dpi", "work"]):
            text = (
                "### 🔬 How Deep Packet Inspection & SNI Extraction Operates\n\n"
                "1. **Packet Capture & Header Unpacking**: Packets enter through the multi-threaded reader. Ethernet and IPv4 headers are stripped to recover the 5-tuple (`src_ip, dst_ip, src_port, dst_port, protocol`).\n\n"
                "2. **Connection Tracking (Fast Path)**: Each flow is hashed (`FiveTupleHash`) and assigned to a worker thread. Flow state machine tracks TCP flags (`SYN`, `SYN-ACK`, `ACK`, `FIN`).\n\n"
                "3. **L7 Protocol Inspection**: When a TCP packet reaches port 443 with payload, the engine parses the TLS Record (type `0x16`), finds Handshake Type `0x01` (Client Hello), and scans TLS extensions for Extension Type `0x0000` (Server Name Indication).\n\n"
                "4. **Rule Matching & PCAP Sanitization**: If the domain or IP matches an active rule, the packet is marked `DROP` and excluded from the output PCAP stream. All other packets are forwarded."
            )
        else:
            text = (
                f"Hello! I am **NetCopilot**, your Deep Packet Inspection and Cybersecurity AI assistant.\n\n"
                f"Currently reviewing `{resp.get('filename', 'your capture')}` with **{summary.get('total_packets', 0)} packets** analyzed.\n\n"
                f"You can ask me to:\n"
                f"- **Analyze detected domains**: *'What domains and SNIs were found?'*\n"
                f"- **Run security threat audit**: *'Check this capture for vulnerabilities and threats'*\n"
                f"- **Recommend firewall rules**: *'What rules should I add to restrict social apps?'*\n"
                f"- **Explain protocols**: *'How does SNI extraction work under TLS encryption?'*\n"
            )

        # Stream text words with micro delays for realistic typing feel
        words = text.split(" ")
        for i, word in enumerate(words):
            yield word + (" " if i < len(words) - 1 else "")
            if i % 3 == 0:
                await asyncio.sleep(0.015)
