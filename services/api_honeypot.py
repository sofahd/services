from sofahutils import DockerComposeService

class ApiHoneypot(DockerComposeService):
    """
    This Class is used to represent an API Honeypot. It is a subclass of the DockerComposeService class.
    """

    def __init__(self, name: str, token: str) -> None:
        """
        Constructor for the ApiHoneypot class.
        :param name: The name of the service.
        :type name: str
        :param token: The token to use for the github link.
        :type token: str
        """

        

        