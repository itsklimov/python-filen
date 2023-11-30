import httpx


async def get_auth_info(email):
    url = 'https://gateway.filen-2.net/v3/auth/info'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Content-Type': 'application/json',
        'Referer': 'https://drive.filen.io/',
        'Checksum': '9dc327903fb2cf490dd16bc50cb2fe4495c96cc2a713c7f2f172cc3097f5afc0a8a6ee07cbe4e01b1e5d4b7d5debe7b863f7ee20c056dbc7ee79859fab58d394',
        'Origin': 'https://drive.filen.io',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'Authorization': 'Bearer null',
        'Connection': 'keep-alive'
    }
    data = {"email": email}

    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json=data)
        return response.json()


# Usage
email = "itsklimov@gmail.com"

# The function is asynchronous, so it must be run in an async context
import asyncio

response = asyncio.run(get_auth_info(email))
print(response)
