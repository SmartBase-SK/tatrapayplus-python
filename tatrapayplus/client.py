import socket
import time
import uuid
from base64 import b64encode
from pathlib import Path
from typing import Optional

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from requests import Response

from tatrapayplus import enums
from tatrapayplus.enums import Urls
from tatrapayplus.errors import TatrapayPlusApiException
from tatrapayplus.helpers import (
    get_simple_status,
    get_saved_card_data,
    remove_special_characters_from_strings,
    trim_and_remove_special_characters,
    remove_diacritics,
    TatrapayPlusLogger,
)
from tatrapayplus.models import (
    GetAccessTokenResponse400,
    Field40XErrorBody,
    Field400ErrorBody,
)
from tatrapayplus.models.appearance_logo_request import AppearanceLogoRequest
from tatrapayplus.models.appearance_request import AppearanceRequest
from tatrapayplus.models.card_pay_update_instruction import CardPayUpdateInstruction
from tatrapayplus.models.initiate_direct_transaction_request import (
    InitiateDirectTransactionRequest,
)
from tatrapayplus.models.initiate_direct_transaction_response import (
    InitiateDirectTransactionResponse,
)
from tatrapayplus.models.initiate_payment_request import InitiatePaymentRequest
from tatrapayplus.models.initiate_payment_response import InitiatePaymentResponse
from tatrapayplus.models.payment_intent_status_response import (
    PaymentIntentStatusResponse,
)
from tatrapayplus.models.payment_method_rules import PaymentMethodRules
from tatrapayplus.models.payment_methods_list_response import PaymentMethodsListResponse


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
        scope: enums.Scope = enums.Scope.TATRAPAYPLUS,
        logger: TatrapayPlusLogger = None,
    ):
        self.logger = logger
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.token: Optional[TatrapayPlusToken] = None
        self.session = requests.Session()
        self.session.headers = self.get_headers()

    def handle_response(self, response, loging=True):
        if loging:
            self.log(response)
        try:
            response.raise_for_status()
        except Exception:
            if Urls.TOKEN_URL in response.url:
                error_body = GetAccessTokenResponse400().from_dict(response.json())
            elif response.status_code == 400:
                error_body = Field400ErrorBody().from_dict(response.json())
            else:
                error_body = Field40XErrorBody().from_dict(response.json())
            raise TatrapayPlusApiException(error_body)
        return response

    def get_access_token(self) -> TatrapayPlusToken:
        token_url = f"{self.base_url}{Urls.TOKEN_URL}"
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope,
        }
        response = self.handle_response(self.session.post(token_url, data=payload))

        return TatrapayPlusToken(
            response.json().get("access_token"), response.json().get("expires_in")
        )

    def get_headers(self):
        if not self.token or self.token.is_expired():
            self.token = self.get_access_token()
        try:
            ip_address = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip_address = "127.0.0.1"
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "X-Request-ID": str(uuid.uuid4()),
            "IP-Address": str(ip_address),
        }

    def create_payment(
        self,
        request: InitiatePaymentRequest,
        redirect_uri: str,
        language: str = "sk",
        preferred_method: Optional[str] = None,
    ) -> InitiatePaymentResponse:
        url = f"{self.base_url}{Urls.PAYMENTS}"
        self.session.headers["Redirect-URI"] = redirect_uri
        self.session.headers["Accept-Language"] = language.lower()
        if preferred_method:
            self.session.headers["Preferred-Method"] = preferred_method

        cleaned_request = remove_special_characters_from_strings(request.to_dict())
        if cleaned_request.get("cardDetail", {}).get("cardHolder"):
            cleaned_request["cardDetail"]["cardHolder"] = (
                trim_and_remove_special_characters(
                    remove_diacritics(cleaned_request["cardDetail"]["cardHolder"])
                )
            )
        response = self.handle_response(self.session.post(url, json=cleaned_request))

        return InitiatePaymentResponse.from_dict(response.json())

    def create_payment_direct(
        self, request: InitiateDirectTransactionRequest, redirect_uri: str
    ) -> InitiateDirectTransactionResponse:
        url = f"{self.base_url}{Urls.DIRECT_PAYMENT}"
        self.session.headers["Redirect-URI"] = redirect_uri

        cleaned_request = remove_special_characters_from_strings(request.to_dict())

        if cleaned_request.get("tdsData", {}).get("cardHolder"):
            cleaned_request["tdsData"]["cardHolder"] = (
                trim_and_remove_special_characters(
                    remove_diacritics(cleaned_request["tdsData"]["cardHolder"])
                )
            )

        response = self.handle_response(self.session.post(url, json=cleaned_request))

        return InitiateDirectTransactionResponse.from_dict(response.json())

    def get_payment_methods(self) -> PaymentMethodsListResponse:
        url = f"{self.base_url}{Urls.PAYMENT_METHODS}"

        response = self.handle_response(self.session.get(url))

        return PaymentMethodsListResponse.from_dict(response.json())

    def get_payment_status(self, payment_id) -> dict:
        url = f"{self.base_url}{Urls.PAYMENTS}/{payment_id}{Urls.STATUS}"

        response = self.handle_response(self.session.get(url), loging=False)
        status = PaymentIntentStatusResponse.from_dict(response.json())
        helpers = {
            "simple_status": get_simple_status(status),
            "saved_card": get_saved_card_data(status),
        }
        response_data = {"status": status, **helpers}
        self.log(response, helpers)
        return response_data

    def update_payment(self, payment_id, request: CardPayUpdateInstruction) -> Response:
        url = f"{self.base_url}{Urls.PAYMENTS}/{payment_id}"
        self.session.headers["Idempotency-Key"] = self.session.headers["X-Request-ID"]
        response = self.handle_response(self.session.patch(url, json=request.to_dict()))

        return response

    def cancel_payment(self, payment_id) -> Response:
        url = f"{self.base_url}{Urls.PAYMENTS}/{payment_id}"
        response = self.handle_response(self.session.delete(url))

        return response

    def get_available_payment_methods(
        self,
        currency_code: Optional[str] = None,
        country_code: Optional[str] = None,
        total_amount: Optional[float] = None,
    ) -> list[PaymentMethodRules]:
        response = self.get_payment_methods()
        all_methods = response.payment_methods

        available_methods = []

        for method in all_methods:
            if currency_code and method.supported_currency:
                supported = [c for c in method.supported_currency]
                if currency_code not in supported:
                    continue

            if total_amount is not None and method.amount_range_rule:
                min_amount = method.amount_range_rule.min_amount or 0
                max_amount = method.amount_range_rule.max_amount or float("inf")
                if not (min_amount <= total_amount <= max_amount):
                    continue

            if country_code and method.supported_country:
                supported = list(method.supported_country)
                if country_code not in supported:
                    continue

            available_methods.append(method)

        return available_methods

    def set_appearance(self, request: AppearanceRequest) -> Response:
        url = f"{self.base_url}{Urls.APPEARANCES}"
        response = self.handle_response(self.session.post(url, json=request.to_dict()))

        return response

    def set_appearance_logo(self, request: AppearanceLogoRequest) -> Response:
        url = f"{self.base_url}{Urls.APPEARANCE_LOGO}"
        response = self.handle_response(self.session.post(url, json=request.to_dict()))
        return response

    def generate_signed_card_id_from_cid(
        cid: str, public_key_content: str | None = None
    ) -> str | None:
        if public_key_content is None:
            try:
                public_key_path = Path(__file__).parent / "../ECID_PUBLIC_KEY_2023.txt"
                public_key_content = public_key_path.read_text(encoding="utf-8")
            except Exception as e:
                print("Error reading public key file:", e)
                return None

        try:
            public_key = serialization.load_pem_public_key(
                public_key_content.encode("utf-8"), backend=default_backend()
            )

            encrypted = public_key.encrypt(
                cid.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            base64_encoded = b64encode(encrypted).decode("utf-8")
            return "\n".join(
                base64_encoded[i : i + 64] for i in range(0, len(base64_encoded), 64)
            )

        except Exception as e:
            print("Encryption error:", e)
            return None

    def log(self, response, additional_response_data=None):
        if self.logger:
            self.logger.log(response, additional_response_data)
