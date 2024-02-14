from sofahutils import DockerComposeService 


class PortSpoofService(DockerComposeService):
    """
    This class is built to represent the port spoof service. It is a subclass of the DockerComposeService class.
    """
    
    def __init__(self, name:str, port:int, banner:str, mode:str, token:str):
        """
        Constructor for the PortSpoofService class. It takes in the name of the service, the port to spoof, the banner to spoof, and the mode to run the service in.

        :param name: The name of the service.
        :type name: str
        :param port: The port to spoof.
        :type port: int
        :param banner: The banner to spoof.
        :type banner: str
        :param mode: The mode to run the service in, can be either "banner" or "http-header"
        :type mode: str
        :param token: The token to use for the github link.
        :type token: str
        """

        service_def = [
            "    container_name: <name>",
            "    restart: unless-stopped",
            "    build: ",
            "      context: ./port_spoof",
            "      args:",
            "        POOF_PORT: '<port>'",
            "        POOF_BANNER: '<banner>'",
            "        POOF_MODE: '<mode>'",
            "        TOKEN: '<token>'",
            "    ports:",
            "      - '<port>:65100'",
            "    networks:",
            "      - log_net",
            "    environment:",
            "      - PYTHONUNBUFFERED=1",
        ]     

        variables = {
            "<name>": name,
            "<port>": port,
            "<banner>": banner,
            "<mode>": mode,
            "<token>": token
        }

        super().__init__(name=name, service_def=service_def, github_link="https://$TOKEN:x-oauth-basic@github.com/sofahd/port_spoof.git", token=token, networks=["log_net"], variables=variables)