from sofahutils import DockerComposeService 


class PortSpoofService(DockerComposeService):
    """
    This class is built to represent the port spoof service. It is a subclass of the DockerComposeService class.
    """
    
    def __init__(self, name:str, port:int, banner:str, mode:str, token:str, log_api_url:str, log_container_name:str) -> None:
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
        :param log_api_url: The url of the log api service. has to include scheme and port (e.g. http://log_api:50005)
        :type log_api_url: str
        :param log_container_name: The name of the log container to depend on.
        :type log_container_name: str
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
            "        LOG_API: '<log_api>'",
            "    ports:",
            "      - '<port>:65100'",
            "    networks:",
            "      - log_net",
            "    depends_on:",
            "      - <log_container_name>",
            "    environment:",
            "      - PYTHONUNBUFFERED=1",
        ]     

        variables = {
            "<name>": name,
            "<port>": port,
            "<banner>": banner,
            "<mode>": mode,
            "<token>": token,
            "<log_api>": log_api_url,
            "<log_container_name>": log_container_name
        }

        super().__init__(name=name, service_def=service_def, github_link="https://$TOKEN:x-oauth-basic@github.com/sofahd/port_spoof.git", token=token, networks=["log_net"], variables=variables)