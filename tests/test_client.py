from tatrapayplus.client import TatrapayPlusClient, TatrapayPlusConfig
from tatrapayplus.models import *


def test_client():
    config = TatrapayPlusConfig(
        base_url='https://api.tatrabanka.sk/tatrapayplus/sandbox',
        client_id='',
        client_secret='',
        redirect_uri='https://tatrabanka.sk/',
    )

    client = TatrapayPlusClient(config)

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
    payment_id = payment_response.paymentId.__root__


    assert payment_id is not None
