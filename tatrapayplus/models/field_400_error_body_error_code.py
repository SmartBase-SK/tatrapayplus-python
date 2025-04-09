from enum import Enum


class Field400ErrorBodyErrorCode(str, Enum):
    CB_AMOUNT_EXCEEDED = "CB_AMOUNT_EXCEEDED"
    CB_ERROR = "CB_ERROR"
    CB_NOT_FOUND = "CB_NOT_FOUND"
    CB_TOO_OLD = "CB_TOO_OLD"
    DUPLICATE_CALL = "DUPLICATE_CALL"
    ILLEGAL_ARGUMENT = "ILLEGAL_ARGUMENT"
    NOT_ALLOWED_OPER = "NOT_ALLOWED_OPER"
    NO_AVAIL_PAY_METH = "NO_AVAIL_PAY_METH"
    NO_CONTRACT = "NO_CONTRACT"
    PAYMENT_NOT_FOUND = "PAYMENT_NOT_FOUND"
    PA_AMOUNT_EXCEEDED = "PA_AMOUNT_EXCEEDED"
    PA_ERROR = "PA_ERROR"
    PA_NOT_FOUND = "PA_NOT_FOUND"
    TOT_AMNT_LOW = "TOT_AMNT_LOW"
    TOT_AMNT_MISMATCH = "TOT_AMNT_MISMATCH"

    def __str__(self) -> str:
        return str(self.value)
