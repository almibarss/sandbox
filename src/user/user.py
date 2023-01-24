from dataclasses import asdict, dataclass


ALLOWED_ROLES = ["ADMIN", "USER"]


@dataclass
class User:
    def getemail(self):
        return self.__dict__.get("email")

    def setemail(self, value):
        if type(value) == property or value is None:
            raise ValidationError("email cannot be None")
        self.__dict__["email"] = value

    def getrole(self):
        return self.__dict__.get("role")

    def setrole(self, value):
        if type(value) == property or value is None:
            self.__dict__["role"] = "USER"
        else:
            self.__dict__["role"] = validate_role(value)

    id: int = None
    email: str = property(getemail, setemail)
    role: str = property(getrole, setrole)
    is_admin = property(lambda self: self.__dict__.get("role") == "ADMIN")

    def asdict(self):
        return asdict(self, dict_factory=lambda x: {k: v for (k, v) in x if v is not None})

    del getemail, setemail, getrole, setrole


def validate_role(value):
    if value.upper() not in ALLOWED_ROLES:
        raise ValidationError(f"unknown role {value} (possible values are {ALLOWED_ROLES}")
    return value.upper()


class ValidationError(Exception):
    def __init__(self, message):
        super().__init__(f'(ValidationError) {message}')
