class Scope:
    TATRAPAYPLUS = "TATRAPAYPLUS"

class Urls:
    TOKEN = "/auth/oauth/v2/token"
    PAYMENTS = "/v1/payments"
    PAYMENT_METHODS = PAYMENTS+"/methods"
    STATUS = "/status"
    APPEARANCES = "/v1/appearances"
    APPEARANCE_LOGO = APPEARANCES+"/logo"
