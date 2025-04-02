import logging
import socket
import time
import uuid
from builtins import str

import requests

from tatrapayplus import enums
from tatrapayplus.enums import Urls
from tatrapayplus.models import *


class TatrapayPlusToken:
    def __init__(self, token: str, expires_in: int):
        self.token = token
        self.expires_in = expires_in + time.time()

    def is_expired(self) -> bool:
        return time.time() >= self.expires_in

    def __str__(self):
        return self.token


class TatrapayPlusClient:
    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scope: enums.Scope = enums.Scope.TATRAPAYPLUS,
    ):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.token: Optional[TatrapayPlusToken] = None
        self.session = requests.Session()
        self.session.headers = self.get_headers()

    def authenticate(self):
        token_url = f"{self.base_url}{Urls.TOKEN}"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
        }
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        self.token = TatrapayPlusToken(
            response.json().get("access_token"), response.json().get("expires_in")
        )

    def get_headers(self):
        if not self.token or self.token.is_expired():
            self.authenticate()
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "X-Request-ID": str(uuid.uuid4()),
            "IP-Address": str(socket.gethostbyname(socket.gethostname())),
        }

    def create_payment(
        self, request: InitiatePaymentRequest
    ) -> InitiatePaymentResponse:
        url = f"{self.base_url}{Urls.PAYMENTS}"
        self.session.headers["Redirect-URI"] = self.redirect_uri
        response = self.session.post(url, data=request.json(exclude_none=True))
        if not response.ok:
            logging.error("Error response:", response.text)

        response.raise_for_status()
        return InitiatePaymentResponse.parse_obj(response.json())

    def get_payment_methods(self) -> PaymentMethodsListResponse:
        url = f"{self.base_url}{Urls.PAYMENT_METHODS}"
        headers = self.get_headers()
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return PaymentMethodsListResponse.parse_obj(response.json())

    def get_available_payment_methods(
        self,
        currency_code: Optional[str] = None,
        country_code: Optional[str] = None,
        total_amount: Optional[float] = None,
    ) -> List[PaymentMethodRules]:
        response = self.get_payment_methods()
        all_methods = response.paymentMethods.__root__

        available_methods = []

        for method in all_methods:
            if currency_code and method.supportedCurrency:
                supported = [c.__root__ for c in method.supportedCurrency.__root__]
                if currency_code not in supported:
                    continue

            if total_amount is not None and method.amountRangeRule:
                min_amount = method.amountRangeRule.minAmount or 0
                max_amount = method.amountRangeRule.maxAmount or float("inf")
                if not (min_amount <= total_amount <= max_amount):
                    continue

            if country_code and method.supportedCountry:
                supported = [
                    supported_country.__root__
                    for supported_country in method.supportedCountry.__root__
                ]
                if country_code not in supported:
                    continue

            available_methods.append(method)

        return available_methods
