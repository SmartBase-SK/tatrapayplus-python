import logging
import socket
import time
import uuid
from builtins import print
from typing import Optional

import requests
from pydantic import BaseModel, HttpUrl

from tatrapayplus import enums
from tatrapayplus.models import InitiatePaymentRequest, InitiatePaymentResponse


class TatrapayPlusConfig(BaseModel):
    base_url: HttpUrl
    client_id: str
    client_secret: str
    redirect_uri: HttpUrl
    scope: str = enums.Scope.TATRAPAYPLUS


class TatrapayPlusToken():
    def __init__(self, token: str, expires_in: int):
        self.token = token
        self.expires_in = expires_in + time.time()

    def is_expired(self) -> bool:
        return time.time() >= self.expires_in

    def __str__(self):
        return self.token


class TatrapayPlusClient:
    def __init__(self, config: TatrapayPlusConfig):
        self.config = config
        self.token: Optional[TatrapayPlusToken] = None

    def authenticate(self):
        token_url = f"{self.config.base_url}/auth/oauth/v2/token"
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scope,
        }
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        self.token = TatrapayPlusToken(response.json().get('access_token'), response.json().get('expires_in'))

    def get_headers(self):
        if not self.token or self.token.is_expired():
            self.authenticate()
        return {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json',
            'X-Request-ID': str(uuid.uuid4()),
            'IP-Address': str(socket.gethostbyname(socket.gethostname())),
        }

    def create_payment(self, request: InitiatePaymentRequest) -> InitiatePaymentResponse:
        url = f"{self.config.base_url}/v1/payments"
        headers = self.get_headers()
        headers['Redirect-URI'] = self.config.redirect_uri
        response = requests.post(url, data=request.json(exclude_none=True), headers=headers)
        if not response.ok:
            logging.error("Error response:", response.text)

        response.raise_for_status()
        return InitiatePaymentResponse.parse_obj(response.json())