import re
import string

import src.link.repo as repo

from src.link.validators import url as is_valid_url

from dataclasses import asdict, dataclass
from datetime import datetime
from itertools import chain
from random import choice

BACKHALF_MIN_LEN = 1
BACKHALF_MAX_LEN = 20


# https://stackoverflow.com/a/54489602
@dataclass
class Link:
    def getbackhalf(self):
        return self.__dict__.get("backhalf")

    def setbackhalf(self, value):
        if type(value) == property or value is None:
            self.__dict__["backhalf"] = new_random_backhalf(len=7)
        else:
            validate_backhalf(value)
            self.__dict__["backhalf"] = value

    def getorigin(self):
        return self.__dict__.get("origin")

    def setorigin(self, value):
        if type(value) == property or value is None:
            raise ValidationError("origin cannot be None")
        validate_url(value)
        self.__dict__["origin"] = value

    backhalf: str = property(getbackhalf, setbackhalf)
    origin: str = property(getorigin, setorigin)
    created_at: str = str(datetime.now())
    updated_at: str = None
    user: str = None

    def asdict(self):
        return asdict(self, dict_factory=lambda x: {k: v for (k, v) in x if v is not None})

    del getbackhalf, setbackhalf, getorigin, setorigin


def new_random_backhalf(len):
    while True:
        new_backhalf = ''.join(choice(list(chain(string.ascii_letters, string.digits))) for c in range(len))
        if not repo.is_taken(new_backhalf):
            return new_backhalf


def validate_backhalf(value):
    format = "^[A-Za-z0-9_-]*$"
    if len(value) < BACKHALF_MIN_LEN:
        raise ValidationError("Backhalf too short. "
                              f"Please provide one in the range {BACKHALF_MIN_LEN}-{BACKHALF_MAX_LEN}")
    if len(value) > BACKHALF_MAX_LEN:
        raise ValidationError("Backhalf too long. "
                              f"Please provide one in the range {BACKHALF_MIN_LEN}-{BACKHALF_MAX_LEN}")
    if not re.match(format, value):
        raise ValidationError(f"Backhalf does not match regex {format}")


def validate_url(value):
    if not is_valid_url(value):
        raise ValidationError("Origin URL is invalid")


class ValidationError(Exception):
    def __init__(self, message):
        super().__init__(f'(ValidationError) {message}')
