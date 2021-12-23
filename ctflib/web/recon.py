import io
import itertools
import typing

from bs4 import BeautifulSoup

from ctflib.web.attack import Attack
from ctflib.web.backend import Request, Response
from ctflib.web.context import context
import urllib.parse


def sus_files(url: str = None):
    assert context.backend is not None, "No backend specified"
    if context.url is not None:
        url = context.url + ("" if url is None else url)
    results = []
    if url.endswith("/"):
        url = url[:-1]
    # More to be added
    sus_urls = [
        "robots.txt",
        ".git/HEAD",
        "flag",
        "flag.txt",
        ".DS_Store",
        "login.php"
    ]
    for i, response in enumerate(context.backend.send_async([Request(url + "/" + sus) for sus in sus_urls])):
        if response.status != 404:
            results.append(url + "/" + sus_urls[i])
    return results


class Form(typing.NamedTuple):
    url: str
    method: str
    inputs: typing.List[str]

    def __check_inputs(self, inputs):
        assert context.backend is not None, "No backend specified"
        for i in inputs:
            if i not in self.inputs:
                raise ValueError(f"{i} is not a valid input")

    def send_request(self, **inputs: typing.Any):
        self.__check_inputs(inputs)
        if self.method.upper() == "POST":
            return context.backend.send_post(self.url, inputs)
        return context.backend.send_get(
            self.url + "?" + "&".join([f"{k}={urllib.parse.quote_plus(v)}" for k, v in inputs.items()]))

    def attack(self, **inputs: str | io.BytesIO | io.TextIOWrapper | Attack) -> typing.List[typing.Tuple[
        typing.Any, Response]]:
        self.__check_inputs(inputs)
        constants = {}
        attack_names = []
        attacks = []
        attack_inputs = []
        for input_name in inputs:
            if isinstance(inputs[input_name], Attack):
                attack_names.append(input_name)
                attacks.append(inputs[input_name])
                attack_inputs.append(inputs[input_name].items())
            else:
                constants[input_name] = inputs[input_name]
        if len(attack_names) == 0:
            return [self.send_request(**inputs)]

        attack_inputs = list(itertools.product(*attack_inputs))
        requests = []
        for i in attack_inputs:
            requests.append(Request(self.url, method=self.method, data=dict(zip(attack_names, i)) | constants))
        responses = context.backend.send_async(requests)
        filtered_responses = []
        for i, response in enumerate(responses):
            added = False
            for attack in attacks:
                attack.handle(response, i)
                if attack.filter(response) and not added:
                    added = True
                    filtered_responses.append((attack_inputs[i], response))
        return filtered_responses


class ReconResults(typing.NamedTuple):
    tech: str | None
    forms: typing.List[Form]


def basic_recon(url: str = None) -> ReconResults:
    assert context.backend is not None, "No backend specified"
    if context.url is not None:
        url = context.url + ("" if url is None else url)
    if url.endswith("/"):
        url = url[:-1]
    header_signatures = {
        "python": ["python", "werkzeug", "gunicorn"],
        "js": ["express"],
        "php": ["php"]
    }
    resp = context.backend.send_get(url)
    headers = ["x-powered-by", "server"]
    found_tech = None
    for header in headers:
        if header in resp.headers:
            val = resp.headers[header].lower()
            for tech, signatures in header_signatures.items():
                for signature in signatures:
                    if signature in val:
                        found_tech = tech
    soup = BeautifulSoup(resp.text, "html.parser")
    page_forms = []
    # Get forms
    forms = soup.find_all("form")
    for form in forms:
        inputs = form.find_all_next("input")
        inputs = [i.attrs.get("name", f"input{num}") for num, i in enumerate(inputs)]
        page_forms.append(Form(url + form.attrs.get("action", ""), form["method"] or "GET", inputs))
    return ReconResults(found_tech, page_forms)
