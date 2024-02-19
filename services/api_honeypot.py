from sofahutils import DockerComposeService

class ApiHoneypot(DockerComposeService):
    """
    This Class is used to represent an API Honeypot. It is a subclass of the DockerComposeService class.
    """

    def __init__(self, name: str, token: str, ext_port:int, log_api_url:str, path_to_answerset:str, nginx_api_net_name:str, log_container_name:str) -> None:
        """
        Constructor for the ApiHoneypot class.

        ---
        :param name: The name of the service.
        :type name: str
        :param token: The token to use for the github link.
        :type token: str
        """

        service_def = [
            "    container_name: <name>",
            "    restart: unless-stopped",
            "    build: ",
            "      context: ./api",
            "      args:",
            "        TOKEN: '<token>'",
            "        EXT_PORT: <ext_port>",
            "        LOG_API: '<log_api>'",
            "    volumes:",
            "      - <path_to_answerset>:/home/api/answerset",
            "    networks:",
            "      - log_net",
            "      - <nginx_api_net_name>",
            "    depends_on:",
            "      <log_container_name>:",
            "        condition: service_healthy",
            "    environment:",
            "      - PYTHONUNBUFFERED=1"
        ]

        variables = {
            "<name>": name,
            "<token>": token,
            "<ext_port>": ext_port,
            "<log_api>": log_api_url,
            "<path_to_answerset>": path_to_answerset,
            "<nginx_api_net_name>": nginx_api_net_name,
            "<log_container_name>": log_container_name
        }

        super().__init__(name=name, service_def=service_def, github_link="https://$TOKEN:x-oauth-basic@github.com/sofahd/api.git", token=token, networks=["log_net", nginx_api_net_name], variables=variables)
        

        