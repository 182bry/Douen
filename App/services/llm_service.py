from __future__ import annotations

from datetime import datetime, timedelta

from openai import OpenAI


class LLMService:

    '''
    Class for generating LLM insights on teh data
    '''

    def __init__(self, state):
        '''
        The app state is passed elsewhere
        '''
        self.state = state


    def build_client(self):

        '''
        Takes some settings from the app state to establish a
        connection with the LLM server

        1) Take the api_key and base_url from the app
        2) If neither received, do nothing and abort
        3) Return client with LLM server url
        '''

        # 1) Take the api_key and base_url from the app
        settings = self.state.server_settings
        api_key = settings.get('llm_api_key', '')
        base_url = settings.get('llm_base_url', '')

        # 2) If neither received, do nothing and abort
        if not api_key or not base_url:
            return None
        # 3) Return client with LLM server url
        return OpenAI(base_url=base_url, api_key=api_key)

    def maybe_refresh_insight(self):

        '''
        The insight does not need to be refreshed every single time.
        
        1) Take the currently active ModeState from the app state (either simulator or network)
        2) If there arent any alert's list, abort
        3) If 20 seconds have passed since the last run, abort
        4) Get a client object. If it didnt work, send an appropriate message and abort
        5) Use the last 5 alerts and last 5 non-benign flows as context for
        LLM insight and create the prompt
        6) Try to initiate the prompt. If it doesnt work, set the insight as an appropriate message
        '''

        # 1) Take the currently active ModeState from the app state (either simulator or network)
        store = self.state.active_store()
        # 2) If there arent any alert's list, abort
        if not store.alerts:
            return
        
        # 3) If 20 seconds have passed since the last run, abort
        now = datetime.now()
        if self.state.llm_last_run and (now - self.state.llm_last_run) < timedelta(seconds=20):
            return
        
        # 4) Get a client object. If it didnt work, send an appropriate message and abort

        client = self.build_client()
        if client is None:
            self.state.set_latest_llm_insight('LLM key or URL is invalid. Please check settings')
            return
        
        # 5) Use the last 5 alerts and last 5 non-benign flows as context for
        # LLM insight and create the prompt

        latest_alerts = list(store.alerts)[:5]
        latest_nb = list(store.not_benign_flows)[:5]
        prompt = (
            'You are a network monitoring assistant. Give a detailed and practical insight about the current network state. '
            'Use the alerts and suspicious flows below. Mention likely risk and one next step. Keep it under 90 words.\n\n'
            f"Alerts:\n{chr(10).join(latest_alerts)}\n\n"
            f"Suspicious flows:\n{chr(10).join(latest_nb)}"
        )

        # 6) Try to initiate the prompt. If it doesnt work, set the insight as an appropriate message
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
            self.state.set_latest_llm_insight(response.choices[0].message.content.strip())
            self.state.llm_last_run = now
        except Exception:
            self.state.set_latest_llm_insight('LLM key or URL is invalid. Please check settings')
