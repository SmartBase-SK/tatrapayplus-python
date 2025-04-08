from card_identifier.card_type import identify_card_type

from tatrapayplus.enums import SimpleStatus
from tatrapayplus.models import (
    PaymentIntentStatusResponse,
    CardPayStatusStructure,
)
from tatrapayplus.models import (
    PaymentMethod,
    CardPayStatus,
    BankTransferStatus,
    PayLaterStatus,
)

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
        payment_status.selectedPaymentMethod, {}
    ).get("accepted", []):
        return SimpleStatus.ACCEPTED

    if plain_status in payment_method_statuses.get(
        payment_status.selectedPaymentMethod, {}
    ).get("rejected", []):
        return SimpleStatus.REJECTED

    return SimpleStatus.PENDING


def get_saved_card_data(payment_status: PaymentIntentStatusResponse) -> dict:
    if (
        payment_status.selectedPaymentMethod != PaymentMethod.CARD_PAY
        or not isinstance(payment_status.status, CardPayStatusStructure)
    ):
        return {}

    comfort_pay = payment_status.status.comfortPay
    masked = (
        payment_status.status.maskedCardNumber.__root__
        if payment_status.status.maskedCardNumber
        else None
    )
    card_type = None

    if masked:
        card_type = identify_card_type(masked)

    saved_card_data = {
        "maskedCardNumber": masked,
        "creditCard": card_type,
    }

    if comfort_pay and comfort_pay.status == "OK" and comfort_pay.cid:
        saved_card_data["cid"]: comfort_pay.cid.__root__

    return saved_card_data
