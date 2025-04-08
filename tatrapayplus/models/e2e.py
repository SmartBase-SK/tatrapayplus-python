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
import pprint
from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError, field_validator
from typing import Any, List, Optional
from typing_extensions import Annotated
from tatrapayplus.models.payment_symbols import PaymentSymbols
from pydantic import StrictStr, Field
from typing import Union, List, Set, Optional, Dict
from typing_extensions import Literal, Self

E2E_ONE_OF_SCHEMAS = ["PaymentSymbols", "str"]

class E2e(BaseModel):
    def to_dict(self) -> Union[str, Dict[str, Any]]:
        """Return the raw JSON-compatible representation of the actual_instance"""
        if isinstance(self.actual_instance, str):
            return self.actual_instance
        elif hasattr(self.actual_instance, "to_dict"):
            return self.actual_instance.to_dict()
        elif hasattr(self.actual_instance, "model_dump"):
            return self.actual_instance.model_dump(by_alias=True, exclude_none=True)
        return self.actual_instance


    def model_dump(self, *args, **kwargs):
        return self.to_dict()

    """
    EndToEndId or paymentSymbols
    """
    # data type: PaymentSymbols
    oneof_schema_1_validator: Optional[PaymentSymbols] = None
    # data type: str
    oneof_schema_2_validator: Optional[Annotated[str, Field(min_length=1, strict=True, max_length=35)]] = Field(default=None, description="Max 35 alphanumeric characters ")
    actual_instance: Optional[Union[PaymentSymbols, str]] = None
    one_of_schemas: Set[str] = { "PaymentSymbols", "str" }

    model_config = ConfigDict(
        validate_assignment=True,
        protected_namespaces=(),
    )


    def __init__(self, *args, **kwargs) -> None:
        if args:
            if len(args) > 1:
                raise ValueError("If a position argument is used, only 1 is allowed to set `actual_instance`")
            if kwargs:
                raise ValueError("If a position argument is used, keyword arguments cannot be used.")
            super().__init__(actual_instance=args[0])
        else:
            super().__init__(**kwargs)


