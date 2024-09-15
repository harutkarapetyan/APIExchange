from pydantic import BaseModel


class CryptoGet(BaseModel):
    crypto_name: str

