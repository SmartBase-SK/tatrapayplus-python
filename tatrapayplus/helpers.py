from tatrapayplus.enums import SimpleStatus
from tatrapayplus.models.bank_transfer_status import BankTransferStatus
from tatrapayplus.models.card_pay_status import CardPayStatus
from tatrapayplus.models.card_pay_status_structure import CardPayStatusStructure
from tatrapayplus.models.comfort_pay_status import ComfortPayStatus
from tatrapayplus.models.pay_later_status import PayLaterStatus
from tatrapayplus.models.payment_intent_status_response import (
    PaymentIntentStatusResponse,
)
from tatrapayplus.models.payment_method import PaymentMethod
import re
import unicodedata
from typing import Any

AMEX = "AMEX"
DISCOVER = "Discover"
MASTERCARD = "MasterCard"
VISA = "Visa"
UNKNOWN = "Unknown"

# Card number constants
AMEX_2 = ("34", "37")
MASTERCARD_2 = ("51", "52", "53", "54", "55")
DISCOVER_2 = ("65",)
DISCOVER_4 = ("6011",)
VISA_1 = ("4",)


def identify_card_type(card_num):
    """
    Identifies the card type based on the card number.
    This information is provided through the first 6 digits of the card number.

    Input: Card number, int or string
    Output: Card type, string
    """

    card_type = UNKNOWN
    card_num = str(card_num)

    # AMEX
    if len(card_num) == 15 and card_num[:2] in AMEX_2:
        card_type = AMEX

    # MasterCard, Visa, and Discover
    elif len(card_num) == 16:
        # MasterCard
        if card_num[:2] in MASTERCARD_2:
            card_type = MASTERCARD

        # Discover
        elif (card_num[:2] in DISCOVER_2) or (card_num[:4] in DISCOVER_4):
            card_type = DISCOVER

        # Visa
        elif card_num[:1] in VISA_1:
            card_type = VISA

    # VISA
    elif (len(card_num) == 13) and (card_num[:1] in VISA_1):
        card_type = VISA

    return card_type


payment_method_statuses = {
    PaymentMethod.QR_PAY: {
        "accepted": [BankTransferStatus.ACSC, BankTransferStatus.ACCC],
        "rejected": [BankTransferStatus.CANC, BankTransferStatus.RJCT],
    },
    PaymentMethod.BANK_TRANSFER: {
        "accepted": [BankTransferStatus.ACSC, BankTransferStatus.ACCC],
        "rejected": [BankTransferStatus.CANC, BankTransferStatus.RJCT],
    },
    PaymentMethod.PAY_LATER: {
        "accepted": [
            PayLaterStatus.LOAN_APPLICATION_FINISHED,
            PayLaterStatus.LOAN_DISBURSED,
        ],
        "rejected": [PayLaterStatus.CANCELED, PayLaterStatus.EXPIRED],
    },
    PaymentMethod.CARD_PAY: {
        "accepted": [CardPayStatus.OK, CardPayStatus.CB],
        "rejected": [CardPayStatus.FAIL],
    },
    PaymentMethod.DIRECT_API: {
        "accepted": [CardPayStatus.OK, CardPayStatus.CB],
        "rejected": [CardPayStatus.FAIL],
    },
}


def get_simple_status(payment_status: PaymentIntentStatusResponse) -> SimpleStatus:
    if not payment_status or not payment_status.status:
        return SimpleStatus.PENDING
    status = payment_status.status

    if isinstance(status, CardPayStatusStructure):
        plain_status = status.status
    elif isinstance(status, BankTransferStatus):
        plain_status = status
    elif isinstance(status, PayLaterStatus):
        plain_status = status
    else:
        return SimpleStatus.PENDING

    if plain_status in payment_method_statuses.get(
        payment_status.selected_payment_method, {}
    ).get("accepted", []):
        return SimpleStatus.ACCEPTED

    if plain_status in payment_method_statuses.get(
        payment_status.selected_payment_method, {}
    ).get("rejected", []):
        return SimpleStatus.REJECTED

    return SimpleStatus.PENDING


def get_saved_card_data(payment_status: PaymentIntentStatusResponse) -> dict:
    if (
        payment_status.selected_payment_method != PaymentMethod.CARD_PAY
        or not isinstance(payment_status.status, CardPayStatusStructure)
    ):
        return {}

    comfort_pay = payment_status.status.comfort_pay
    masked = (
        payment_status.status.masked_card_number
        if payment_status.status.masked_card_number
        else None
    )
    card_type = None

    if masked:
        card_type = identify_card_type(masked)

    saved_card_data = {
        "maskedCardNumber": masked,
        "creditCard": card_type,
    }

    if comfort_pay and comfort_pay.status == ComfortPayStatus.OK and comfort_pay.cid:
        saved_card_data["cid"] = comfort_pay.cid

    return saved_card_data


def remove_diacritics(s: str) -> str:
    s = unicodedata.normalize("NFD", s)
    s = re.sub(r"[\u0300-\u036f]", "", s)
    s = re.sub(r"[^0-9a-zA-Z.@_ \-]", "", s)  # matches [^0-9a-zA-Z.@_ -]
    return s


def trim_and_remove_special_characters(s: str) -> str:
    s = re.sub(r"[<>|`\\]", " ", s)
    return s.strip()


def remove_special_characters_from_strings(obj: Any) -> Any:
    if isinstance(obj, str):
        return trim_and_remove_special_characters(obj)
    elif isinstance(obj, list):
        return [remove_special_characters_from_strings(item) for item in obj]
    elif isinstance(obj, dict):
        return {
            key: remove_special_characters_from_strings(value)
            for key, value in obj.items()
        }
    return obj
