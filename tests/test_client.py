import os
from unittest.mock import MagicMock, patch

import pytest

from tatrapayplus.client import TatrapayPlusClient
from tatrapayplus.enums import SimpleStatus
from tatrapayplus.models import *


@pytest.fixture
def tatrapay_client():
    return TatrapayPlusClient(
        "https://api.tatrabanka.sk/tatrapayplus/sandbox",
        os.environ["TATRAPAY_CLIENT_ID"],
        os.environ["TATRAPAY_CLIENT_SECRET"],
        "https://tatrabanka.sk/",
    )


def get_minimal_payment_data():
    return InitiatePaymentRequest(
        basePayment=BasePayment(
            instructedAmount=Amount(
                amountValue=AmountValue(__root__=120),
                currency=CurrencyCode(__root__="EUR"),
            ),
            endToEnd=E2e(__root__=EndToEndId(__root__="ORDER123456")),
        ),
        bankTransfer={},
    )


def test_create_minimal_payment(tatrapay_client):
    payment_response = tatrapay_client.create_payment(get_minimal_payment_data())
    assert payment_response.paymentId.__root__ is not None


def test_create_full_payment(tatrapay_client):

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


def test_create_direct_payment(tatrapay_client):
    payment_data = InitiateDirectTransactionRequest(
        amount=Amount(
            amountValue=AmountValue(__root__=30.0),
            currency=CurrencyCode(__root__="EUR"),
        ),
        endToEnd=E2e(
            __root__=PaymentSymbols(
                variableSymbol=VariableSymbol(__root__="123456"),
                specificSymbol=SpecificSymbol(__root__="0244763"),
                constantSymbol=ConstantSymbol(__root__="389"),
            )
        ),
        isPreAuthorization=True,
        tdsData=DirectTransactionTDSData(
            cardHolder=CardHolder(__root__="Janko Hruska"),
            email=Email(__root__="janko.hruska@example.com"),
            phone=Phone(__root__="+421900000000"),
            billingAddress=Address(
                streetName="Ulica",
                buildingNumber="35",
                townName="Bratislava",
                postCode="81101",
                country=CountryCode(__root__="SK"),
            ),
            shippingAddress=Address(
                streetName="Ulica",
                buildingNumber="35",
                townName="Bratislava",
                postCode="81101",
                country=CountryCode(__root__="SK"),
            ),
        ),
        ipspData=DirectTransactionIPSPData(
            subMerchantId="5846864684",
            name="Test Predajca",
            location="Bratislava",
            country=CountryCode(__root__="SK"),
        ),
        token=Token(
            __root__=ApplePayToken(
                token=Token1(
                    header=Header(
                        ephemeralPublicKey="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELAfD ie0Ie1TxCcrFt69BzcQ52+F+Fhm5mDw6pMR54AzoFMgdGPRbqoLtFpoSe0FI/m0cqRMOVM2W4Bz9jVZZHA==",
                        publicKeyHash="LjAAyv6vb6jOEkjfG7L1a5OR2uCTHIkB61DaYdEWD",
                        transactionId="0c4352c073ad460044517596dbbf8fe503a837138c8c2de18fddb37ca3ec5295",
                    ),
                    data="M8i9PNK4yXtKO3xmOn6uyYOWmQ+iX9/Oc0EWHJZnPZ/IAEe2UYNCfely3dgq3veEygmQcl0s8lvMeCIZAbbBvbZW...",
                    signature="bNEa18hOrgG/oFk/o0CtYR01vhm+34RbStas1T+tkFLpP0eG5A+...",
                    version="EC_v1",
                )
            )
        ),
    )

    payment_response = tatrapay_client.create_payment_direct(payment_data)

    assert payment_response.paymentId.__root__ is not None


def test_get_payment_methods(tatrapay_client):
    response = tatrapay_client.get_payment_methods()
    assert response.paymentMethods.__root__ is not None


def test_get_available_payment_methods(tatrapay_client):
    expected_methods = {
        PaymentMethod.BANK_TRANSFER,
        PaymentMethod.CARD_PAY,
        PaymentMethod.QR_PAY,
        PaymentMethod.DIRECT_API,
    }
    response = tatrapay_client.get_available_payment_methods("EUR", "SK", 10)

    assert expected_methods.issubset([p.paymentMethod for p in response])


def test_cancel_payment(tatrapay_client):
    cancel_payment_response = tatrapay_client.cancel_payment(
        tatrapay_client.create_payment(get_minimal_payment_data()).paymentId.__root__
    )
    assert cancel_payment_response.ok


@patch("tatrapayplus.client.requests.Session.patch")
def test_update_payment_mocked(mock_request, tatrapay_client):

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.ok = True
    mock_request.return_value = mock_response

    update_data = CardPayUpdateInstruction(
        operationType=OperationType.CHARGEBACK,
        amount=AmountValue(__root__=120),
    )
    payment_update_response = tatrapay_client.update_payment("123", update_data)
    assert payment_update_response.ok


def test_get_payment_status(tatrapay_client):
    payment_status = tatrapay_client.get_payment_status(
        tatrapay_client.create_payment(get_minimal_payment_data()).paymentId.__root__
    )
    assert payment_status is not None


def test_set_appearance(tatrapay_client):
    appearance_data = AppearanceRequest(
        theme="SYSTEM",
        surfaceAccent=ColorAttribute(colorDarkMode="#fff", colorLightMode="#fff"),
        tintAccent=ColorAttribute(colorDarkMode="#fff", colorLightMode="#fff"),
        tintOnAccent=ColorAttribute(colorDarkMode="#fff", colorLightMode="#fff"),
    )
    response = tatrapay_client.set_appearance(appearance_data)
    assert response.ok


@patch("tatrapayplus.client.requests.Session.post")
def test_set_appearance_logo_mocked(mock_request, tatrapay_client):

    mock_response = MagicMock()
    mock_response.status_code = 201
    mock_response.ok = True
    mock_request.return_value = mock_response

    logo_data = AppearanceLogoRequest(
        logoImage="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX///+/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD/aNpbtEAAAAASUVORK5CYII",
    )

    response = tatrapay_client.set_appearance_logo(logo_data)

    assert response.ok


@patch("tatrapayplus.client.requests.Session.get")
def test_saved_card_and_simple_status_data_mocked(mock_request, tatrapay_client):

    mocked_status_response = {
        "selectedPaymentMethod": "CARD_PAY",
        "authorizationStatus": "AUTH_DONE",
        "status": {
            "status": "OK",
            "currency": "EUR",
            "maskedCardNumber": "440577******5558",
        },
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.ok = True
    mock_response.json.return_value = mocked_status_response

    mock_request.return_value = mock_response

    response = tatrapay_client.get_payment_status("123")

    assert response["simple_status"] == SimpleStatus.ACCEPTED
    assert response["saved_card"]["creditCard"] == "Visa"
