from abc import ABC, abstractmethod
from django_keycloak_auth.utils import CommonUtils


class CastKeycloakAttributeBase(ABC):
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.attribute_names = None

    @abstractmethod
    def apply(self):
        pass


class CastDateKeycloakAttribute(CastKeycloakAttributeBase):
    def __init__(self, key, value):
        super().__init__(key, value)
        self.attribute_names = ['birthdate']

    def apply(self):
        if self.key in self.attribute_names:
            return CommonUtils.convert_gregorian_to_date(self.value) if CommonUtils.is_date_string(self.value) else None
        return self.value
