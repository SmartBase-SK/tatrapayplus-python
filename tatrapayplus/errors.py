from typing import Union

from tatrapayplus.models import (
    GetAccessTokenResponse400,
    Field40XErrorBody,
    Field400ErrorBody,
)


class TatrapayPlusApiException(Exception):
    def __init__(
        self,
        error_body: Union[
            GetAccessTokenResponse400, Field40XErrorBody, Field400ErrorBody
        ],
    ):
        self.error_body = error_body

    def __str__(self) -> str:
        return str(self.error_body.to_dict())
