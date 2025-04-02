import os

import pytest

from tatrapayplus.client import TatrapayPlusClient
from tatrapayplus.models import *


@pytest.fixture
def tatrapay_client():
    return TatrapayPlusClient(
        "https://api.tatrabanka.sk/tatrapayplus/sandbox",
        os.environ["TATRAPAY_CLIENT_ID"],
        os.environ["TATRAPAY_CLIENT_SECRET"],
        "https://tatrabanka.sk/",
    )


def test_minimal_payment(tatrapay_client):
    payment_data = InitiatePaymentRequest(
        basePayment=BasePayment(
            instructedAmount=Amount(
                amountValue=AmountValue(__root__=10),
                currency=CurrencyCode(__root__="EUR"),
            ),
            endToEnd=E2e(__root__=EndToEndId(__root__="ORDER123456")),
        ),
        bankTransfer={},
    )

    payment_response = tatrapay_client.create_payment(payment_data)
    assert payment_response.paymentId.__root__ is not None


def test_full_payment(tatrapay_client):

    payment_data = InitiatePaymentRequest(
        basePayment=BasePayment(
            instructedAmount=Amount(
                amountValue=AmountValue(__root__=10.0),
                currency=CurrencyCode(__root__="EUR"),
            ),
            endToEnd=E2e(__root__=EndToEndId(__root__="ORDER123456")),
        ),
        bankTransfer=BankTransfer(),
        payLater=PayLater(
            order=Order(
                orderNo=OrderNo(__root__="ORDER123456"),
                orderItems=OrderItems(
                    __root__=[
                        OrderItem(
                            quantity=Quantity(__root__=1),
                            totalItemPrice=TotalItemPrice(__root__=10.0),
                            itemDetail=ItemDetail(
                                itemDetailSK=ItemDetailLangUnit(
                                    itemName=ItemName(__root__="Testovací produkt"),
                                    itemDescription=ItemDescription(
                                        __root__="Popis produktu"
                                    ),
                                ),
                                itemDetailEN=ItemDetailLangUnit(
                                    itemName=ItemName(__root__="Test Product"),
                                    itemDescription=ItemDescription(
                                        __root__="Product description"
                                    ),
                                ),
                            ),
                            itemInfoURL=ItemInfoURL(__root__="https://tatrabanka.sk"),
                        )
                    ]
                ),
                preferredLoanDuration=PreferredLoanDuration(__root__=12),
                downPayment=DownPayment(__root__=1.0),
            ),
            capacityInfo=CapacityInfo(
                monthlyIncome=MonthlyIncome(__root__=2000.0),
                monthlyExpenses=MonthlyExpenses(__root__=800.0),
                numberOfChildren=NumberOfChildren(__root__=1),
            ),
        ),
        cardDetail=CardDetail(
            cardPayLangOverride=CardPayLangOverride.SK,
            isPreAuthorization=True,
            cardHolder=CardHolder(__root__="Janko Hruska"),
            billingAddress=Address(
                streetName="Hlavna Ulica",
                buildingNumber="123",
                townName="Bratislava",
                postCode="81101",
                country=CountryCode(__root__="SK"),
            ),
            shippingAddress=Address(
                streetName="Hlavna Ulica",
                buildingNumber="123",
                townName="Bratislava",
                postCode="81101",
                country=CountryCode(__root__="SK"),
            ),
            comfortPay=CardIdentifierOrRegister(
                __root__=RegisterForComfortPayObj(
                    registerForComfortPay=RegisterForComfortPay(__root__=True)
                )
            ),
        ),
        userData=UserData(
            firstName=Name(__root__="Janko"),
            lastName=Name(__root__="Hruska"),
            email=Email(__root__="janko.hruska@example.com"),
        ),
    )

    payment_response = tatrapay_client.create_payment(payment_data)
    assert payment_response.paymentId.__root__ is not None
