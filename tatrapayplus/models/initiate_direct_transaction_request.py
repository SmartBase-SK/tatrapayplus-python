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

from pydantic import BaseModel, ConfigDict, Field, StrictBool
from typing import Any, ClassVar, Dict, List, Optional
from tatrapayplus.models.amount import Amount
from tatrapayplus.models.direct_transaction_ipsp_data import DirectTransactionIPSPData
from tatrapayplus.models.direct_transaction_tds_data import DirectTransactionTDSData
from tatrapayplus.models.e2e import E2e
from tatrapayplus.models.token import Token
from typing import Optional, Set
from typing_extensions import Self

class InitiateDirectTransactionRequest(BaseModel):
    """
    Body for direct transaction initiation
    """ # noqa: E501
    amount: Amount
    end_to_end: E2e = Field(alias="endToEnd")
    is_pre_authorization: Optional[StrictBool] = Field(default=None, description="If true - pre-authorization transaction", alias="isPreAuthorization")
    tds_data: DirectTransactionTDSData = Field(alias="tdsData")
    ipsp_data: Optional[DirectTransactionIPSPData] = Field(default=None, alias="ipspData")
    token: Token
    __properties: ClassVar[List[str]] = ["amount", "endToEnd", "isPreAuthorization", "tdsData", "ipspData", "token"]

    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        protected_namespaces=(),
    )


    def to_str(self) -> str:
        """Returns the string representation of the model using alias"""
        return pprint.pformat(self.model_dump(by_alias=True))

    def to_json(self) -> str:
        """Returns the JSON representation of the model using alias"""
        # TODO: pydantic v2: use .model_dump_json(by_alias=True, exclude_unset=True) instead
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> Optional[Self]:
        """Create an instance of InitiateDirectTransactionRequest from a JSON string"""
        return cls.from_dict(json.loads(json_str))

    def to_dict(self) -> Dict[str, Any]:
        """Return the dictionary representation of the model using alias.

        This has the following differences from calling pydantic's
        `self.model_dump(by_alias=True)`:

        * `None` is only added to the output dict for nullable fields that
          were set at model initialization. Other fields with value `None`
          are ignored.
        """
        excluded_fields: Set[str] = set([
        ])

        _dict = self.model_dump(
            by_alias=True,
            exclude=excluded_fields,
            exclude_none=True,
        )
        # override the default output from pydantic by calling `to_dict()` of amount
        if self.amount:
            _dict['amount'] = self.amount.to_dict()
        # override the default output from pydantic by calling `to_dict()` of end_to_end
        if self.end_to_end:
            _dict['endToEnd'] = self.end_to_end.to_dict()
        # override the default output from pydantic by calling `to_dict()` of tds_data
        if self.tds_data:
            _dict['tdsData'] = self.tds_data.to_dict()
        # override the default output from pydantic by calling `to_dict()` of ipsp_data
        if self.ipsp_data:
            _dict['ipspData'] = self.ipsp_data.to_dict()
        # override the default output from pydantic by calling `to_dict()` of token
        if self.token:
            _dict['token'] = self.token.to_dict()
        return _dict

    @classmethod
    def from_dict(cls, obj: Optional[Dict[str, Any]]) -> Optional[Self]:
        """Create an instance of InitiateDirectTransactionRequest from a dict"""
        if obj is None:
            return None

        if not isinstance(obj, dict):
            return cls.model_validate(obj)

        _obj = cls.model_validate({
            "amount": Amount.from_dict(obj["amount"]) if obj.get("amount") is not None else None,
            "endToEnd": E2e.from_dict(obj["endToEnd"]) if obj.get("endToEnd") is not None else None,
            "isPreAuthorization": obj.get("isPreAuthorization"),
            "tdsData": DirectTransactionTDSData.from_dict(obj["tdsData"]) if obj.get("tdsData") is not None else None,
            "ipspData": DirectTransactionIPSPData.from_dict(obj["ipspData"]) if obj.get("ipspData") is not None else None,
            "token": Token.from_dict(obj["token"]) if obj.get("token") is not None else None
        })
        return _obj


