import asyncio
import typing
from typing import Any


class Response(typing.NamedTuple):
    status: int
    text: str
    headers: dict

class Request(typing.NamedTuple):
    url: str
    method: str = "GET"
    headers: dict|None = None
    data: dict|None = None

class Backend:
    session: Any
    engine_name: str
    
    def __init__(self, engine_name: str):
        self.engine_name = engine_name
        
    def get_cookies(self) -> dict:
        raise NotImplementedError()
    
    def set_cookie(self, cookie_name: str, cookie_value: str):
        raise NotImplementedError()
    
    def send_post(self, url: str, data: dict, headers: dict = None) -> Response:
        raise NotImplementedError()
    
    def send_get(self, url: str, headers: dict = None) -> Response:
        raise NotImplementedError()
    
    def send_async(self, requests: typing.List[Request]) -> typing.List[Response]:
        raise NotImplementedError()
    

class RequestsBackend(Backend):
    import requests
    session: requests.Session
    def __init__(self, impersonate_browser: bool = True):
        super().__init__("requests")
        import requests
        self.requests = requests
        self.session = requests.Session()
        if impersonate_browser:
            self.session.headers["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        
    def get_cookies(self) -> dict:
        return self.session.cookies.get_dict()
    
    def set_cookie(self, cookie_name: str, cookie_value: str):
        self.session.cookies.set(cookie_name, cookie_value)
    
    def send_post(self, url: str, data: dict, headers: dict = None) -> Response:
        resp = self.session.post(url, data=data, headers=headers)
        return Response(resp.status_code, resp.text, resp.headers)
    
    def send_get(self, url: str, headers: dict = None) -> Response:
        resp = self.session.get(url, headers=headers)
        return Response(resp.status_code, resp.text, resp.headers)
    
    def send_async(self, requests: typing.List[Request]) -> typing.List[Response]:
        responses = []
        for req in requests:
            if req.method == "POST":
                responses.append(self.session.post(req.url, data=req.data, headers=req.headers))
            else:
                responses.append(self.session.get(req.url, headers=req.headers))
        return [Response(resp.status_code, resp.text, resp.headers) for resp in responses]
        
class AsyncBackend(Backend):
    import aiohttp
    event_loop: asyncio.AbstractEventLoop
    session: aiohttp.ClientSession
    def __init__(self, impersonate_browser: bool = True):
        import aiohttp
        super().__init__("aiohttp")
        self.event_loop = asyncio.get_event_loop()
        self.session = aiohttp.ClientSession()
        if impersonate_browser:
            self.session.headers["User-Agent"] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
        
    def get_cookies(self) -> dict:
        return dict((cookie.name, cookie.value) for cookie in self.session.cookie_jar)
    
    def set_cookie(self, cookie_name: str, cookie_value: str):
        self.session.cookie_jar.update_cookies({cookie_name: cookie_value})
        
    def send_post(self, url: str, data: dict, headers: dict = None) -> Response:
        async def _send_post():
            async with self.session.post(url, data=data, headers=headers) as resp:
                return Response(resp.status, await resp.text(), resp.headers)
        return self.event_loop.run_until_complete(_send_post())
    
    def send_get(self, url: str, headers: dict = None) -> Response:
        async def _send_get():
            async with self.session.get(url, headers=headers) as resp:
                return Response(resp.status, await resp.text(), resp.headers)
        return self.event_loop.run_until_complete(_send_get())
    
    def send_async(self, requests: typing.List[Request]) -> typing.List[Response]:
        async def _send_async():
            tasks = []
            for req in requests:
                if req.method == "POST":
                    tasks.append(self.session.post(req.url, data=req.data, headers=req.headers))
                else:
                    tasks.append(self.session.get(req.url, headers=req.headers))
            responses = await asyncio.gather(*tasks)
            return [Response(resp.status, await resp.text(), resp.headers) for resp in responses]
        return self.event_loop.run_until_complete(_send_async())

