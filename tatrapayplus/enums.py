from enum import Enum


class Scope(str, Enum):
    TATRAPAYPLUS = "TATRAPAYPLUS"


class Urls:
    AUTH_ENDPOINT = "/auth/oauth/v2/token"
    PAYMENTS = "/v1/payments"
    DIRECT_PAYMENT = "/v1/payments-direct"
    PAYMENT_METHODS = PAYMENTS + "/methods"
    STATUS = "/status"
    APPEARANCES = "/v1/appearances"
    APPEARANCE_LOGO = APPEARANCES + "/logo"


class SimpleStatus(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    PENDING = "PENDING"
    CAPTURE = "CAPTURE"
    REJECTED = "REJECTED"
