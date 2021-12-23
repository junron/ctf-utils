import random

from ctflib.web.backend import Backend


class context:
    backend: Backend = None
    url: str = None
    not_found = "NOT_FOUND"+str(random.randint(0, 1000))
    not_found2 = "NOT_FOUND"+str(random.randint(0, 1000))
