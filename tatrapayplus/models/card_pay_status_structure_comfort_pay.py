# coding: utf-8

"""
    TatraPayPlus API

    No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)

    The version of the OpenAPI document: 0.0.1_2024-05-27v1
    Generated by OpenAPI Generator (https://openapi-generator.tech)

    Do not edit the class manually.
"""  # noqa: E501


from __future__ import annotations
import pprint
import re  # noqa: F401
import json

from pydantic import BaseModel, ConfigDict, Field, field_validator
from typing import Any, ClassVar, Dict, List, Optional
from typing_extensions import Annotated
from tatrapayplus.models.comfort_pay_status import ComfortPayStatus
from typing import Optional, Set
from typing_extensions import Self

class CardPayStatusStructureComfortPay(BaseModel):
    """
    CardPayStatusStructureComfortPay
    """ # noqa: E501
    status: ComfortPayStatus
    cid: Optional[Annotated[str, Field(strict=True, max_length=18)]] = Field(default=None, description="Card identifier for ComfortPay")
    __properties: ClassVar[List[str]] = ["status", "cid"]


