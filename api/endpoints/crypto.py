from fastapi import APIRouter, Depends, HTTPException, status
from schemas.crypto_schemas import (
    CryptoGet

)

router = APIRouter(
    prefix='/crypto',
    tags=["Crypto apps"]
)


import requests
import configparser

config = configparser.ConfigParser()

config.read('../app/core/config.ini')

api_key = config['API']['key']

headers = {
    'X-CMC_PRO_API_KEY': f'{api_key}'
          }


@router.get("/by-name/price/crypto_name")
def get_crypto(data: str):
    response = requests.get("https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest",
                            headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Error fetching data from CoinMarketCap API")

    response_json = response.json()

    for crypto in response_json['data']:
        if crypto['name'].lower() == data.lower():
            return {"name": crypto['name'], "price": crypto['quote']['USD']['price']}

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"Cryptocurrency {data} not found")


@router.get("/top-ten-coins/{quantity}")
def get_top_ten_coins(quantity: int):
    response = requests.get("https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest",
                            headers=headers)
    if quantity < 1 or quantity > 100:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="The entered number must not be less than 1 and not exceed 100")

    if response.status_code != 200:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="Error fetching data from CoinMarketCap API")

    response_json = response.json()
    response_json_data = response_json["data"][:quantity]

    result = sorted([{"name": coin["name"], "price": coin["quote"]["USD"]["price"]} for coin in response_json_data],
                    key=lambda x: x["price"])

    return result














