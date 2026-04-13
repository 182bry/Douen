from __future__ import annotations

from datetime import datetime, timedelta
from openai import OpenAI

# connecting to class LLM API. Using lab 5 code
class LLMService:
    def __init__(self, state):
        self.state = state

    def _build_client(self):
        settings = self.state.server_settings
        api_key = settings.get('llm_api_key', '')
        base_url = settings.get('llm_base_url', '')
        if not api_key or not base_url:
            return None
        return OpenAI(base_url=base_url, api_key=api_key)

    # create a response from an LLM with current alerts and suspicious flows for context
    def maybe_refresh_insight(self):
        if not self.state.alerts:
            return
        now = datetime.now()
        if self.state.llm_last_run and (now - self.state.llm_last_run) < timedelta(seconds=20):
            return
        client = self._build_client()
        if client is None:
            self.state.latest_llm_insight = (
                'LLM insight is disabled. Add LLM_API_KEY on the Connection page or in .env to enable Synapse analysis.'
            )
            return
        latest_alerts = list(self.state.alerts)[:5]
        latest_nb = list(self.state.not_benign_flows)[:5]
        prompt = (
            'You are a network monitoring assistant. Give a detailed and practical insight about the current network state. '
            'Use the alerts and suspicious flows below. Mention likely risk and one next step. Keep it under 90 words.\n\n'
            f"Alerts:\n{chr(10).join(latest_alerts)}\n\n"
            f"Suspicious flows:\n{chr(10).join(latest_nb)}"
        )
        try:
            response = client.chat.completions.create(
                model=self.state.server_settings.get('llm_model', 'llama3.3-70b-instruct'),
                messages=[
                    {
                        'role': 'system',
                        'content': 'You are a concise security analyst. Give plain English monitoring insights.'
                    },
                    {'role': 'user', 'content': prompt},
                ],
                max_tokens=120,
                temperature=0.3,
            )
            self.state.latest_llm_insight = response.choices[0].message.content.strip()
            self.state.llm_last_run = now
        except Exception as exc:
            self.state.latest_llm_insight = f'LLM insight failed: {exc}'
