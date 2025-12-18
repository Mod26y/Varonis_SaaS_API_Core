class VaronisError(Exception):
    pass

class AuthenticationError(VaronisError):
    pass

class ApiRequestError(VaronisError):
    pass

class InvalidQueryError(VaronisError):
    pass

class MappingError(VaronisError):
    pass
