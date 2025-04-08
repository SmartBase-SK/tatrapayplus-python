# coding: utf-8

"""
    TatraPayPlus API

    No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

    The version of the OpenAPI document: 0.0.1_2024-05-27v1
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


from __future__ import annotations
import json
from enum import Enum
from typing_extensions import Self


class PaymentMethod(str, Enum):
    """
    TatraPayPlus enumaration
    """

    """
    allowed enum values
    """
    BANK_TRANSFER = 'BANK_TRANSFER'
    CARD_PAY = 'CARD_PAY'
    PAY_LATER = 'PAY_LATER'
    DIRECT_API = 'DIRECT_API'
    QR_PAY = 'QR_PAY'

    @classmethod
    def from_json(cls, json_str: str) -> Self:
        """Create an instance of PaymentMethod from a JSON string"""
        return cls(json.loads(json_str))


