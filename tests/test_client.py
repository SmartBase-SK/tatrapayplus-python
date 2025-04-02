import os

import pytest

from tatrapayplus.client import TatrapayPlusClient, TatrapayPlusConfig
from tatrapayplus.models import *


@pytest.fixture
def tatrapay_config():
    return TatrapayPlusConfig(
        base_url='https://api.tatrabanka.sk/tatrapayplus/sandbox',
        client_id=os.environ['TATRAPAY_CLIENT_ID'],
        client_secret=os.environ['TATRAPAY_CLIENT_SECRET'],
        redirect_uri='https://tatrabanka.sk/',
    )


def test_minimal_payment(tatrapay_config):
    client = TatrapayPlusClient(tatrapay_config)

    payment_data = InitiatePaymentRequest(
        basePayment=BasePayment(
            instructedAmount=Amount(
                amountValue=AmountValue(__root__=10),
                currency=CurrencyCode(__root__="EUR")
            ),
            endToEnd=E2e(__root__=EndToEndId(__root__="ORDER123456"))
        ),
        bankTransfer={}
    )

    payment_response = client.create_payment(payment_data)
    print(payment_response)
    assert payment_response.paymentId.__root__ is not None
