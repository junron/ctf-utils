import string
import aiohttp

import asyncio


async def fetch(url, session):
    async with session.get(url) as response:
        return await response.read()


async def _search(url, charset):
    async with aiohttp.ClientSession() as session:
        negative = await fetch(url, session)
        found = ""
        while True:
            tasks = []
            for char in charset:
                new_url = url.replace("FUZZ", found + char)
                task = asyncio.ensure_future(fetch(new_url, session))
                tasks.append(task)
            responses = await asyncio.gather(*tasks)
            for i, x in enumerate(responses):
                if x != negative:
                    found += charset[i]
                    print(found)
                    break
            else:
                print("Not found")
                break


def search(url, charset=string.ascii_lowercase + string.digits + "_"):
    loop = asyncio.get_event_loop()
    loop.run_until_complete(_search(url, charset))
