import logging
import socket
import time
import uuid
from typing import Optional
from builtins import str
import requests
from pydantic import BaseModel, HttpUrl

from tatrapayplus import enums
from tatrapayplus.models import InitiatePaymentRequest, InitiatePaymentResponse


class TatrapayPlusToken():
    def __init__(self, token: str, expires_in: int):
        self.token = token
        self.expires_in = expires_in + time.time()

    def is_expired(self) -> bool:
        return time.time() >= self.expires_in

    def __str__(self):
        return self.token


class TatrapayPlusClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str, redirect_uri: str, scope: enums.Scope = enums.Scope.TATRAPAYPLUS):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.token: Optional[TatrapayPlusToken] = None

    def authenticate(self):
        token_url = f"{self.base_url}/auth/oauth/v2/token"
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope,
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
        url = f"{self.base_url}/v1/payments"
        headers = self.get_headers()
        headers['Redirect-URI'] = self.redirect_uri
        response = requests.post(url, data=request.json(exclude_none=True), headers=headers)
        if not response.ok:
            logging.error("Error response:", response.text)

        response.raise_for_status()
        return InitiatePaymentResponse.parse_obj(response.json())
