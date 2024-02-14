from sofahutils import DockerComposeService

class LogApiService(DockerComposeService):
    """
    This class is used to represent the log-api service. It is a subclass of the DockerComposeService class.
    """

    def __init__(self, name:str, port:int, log_folder_path:str, token:str) -> None:
        """
        Constructor for the LogApiService class.
        """
        service_def = [
            "    container_name: <name>",
            "    restart: unless-stopped",
            "    build: ",
            "      context: ./log-api",
            "      args:",
            "        WAITRESS_PORT: <port>",
            "    networks:",
            "      - log_net",
            "    environment:",
            "      - PYTHONUNBUFFERED=1",
            "    volumes:",
            "      - <path>:/home/api/log_data",
            "    healthcheck:",
            "      test: ['CMD-SHELL', 'curl -f http://localhost:<port>/health || exit 1']",
            "      interval: 30s",
            "      timeout: 10s",
            "      retries: 3",
            "      start_period: 10s"
        ]

        variables = {
            "<name>": name,
            "<port>": port,
            "<path>": log_folder_path
        }
        super().__init__(name=name, service_def=service_def, github_link="https://$TOKEN:x-oauth-basic@github.com/sofahd/log-api.git", token=token, networks=["log_net"], variables=variables)
