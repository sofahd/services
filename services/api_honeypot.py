from sofahutils import DockerComposeService
import json

class ApiHoneypot(DockerComposeService):
    """
    This Class is used to represent an API Honeypot. It is a subclass of the DockerComposeService class.
    """

    def __init__(self, name: str, token: str, ext_port:int, log_api_url:str, nginx_api_net_name:str, log_container_name:str, answerset:dict) -> None:
        """
        Constructor for the ApiHoneypot class.

        ---
        :param name: The name of the service.
        :type name: str
        :param token: The token to use for the github link.
        :type token: str
        :param ext_port: The external port to run the service on.
        :type ext_port: int
        :param log_api_url: The url of the log api service. has to include scheme and port (e.g. http://log_api:50005)
        :type log_api_url: str
        :param nginx_api_net_name: The name of the network to attach the service to.
        :type nginx_api_net_name: str
        :param log_container_name: The name of the log container to depend on.
        :type log_container_name: str
        :param answerset: The answerset for the honeypot.
        :type answerset: dict
        """

        self.answerset = answerset

        service_def = [
            "    container_name: <name>",
            "    restart: unless-stopped",
            "    build: ",
            "      context: ./<name>",
            "      args:",
            "        TOKEN: '<token>'",
            "        EXT_PORT: <ext_port>",
            "        LOG_API: '<log_api>'",
            "    volumes:",
            "      - ./<name>/data/answerset:/home/api/answerset",
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
            "<nginx_api_net_name>": nginx_api_net_name,
            "<log_container_name>": log_container_name
        }

        super().__init__(name=name, service_def=service_def, github_link="https://$TOKEN:x-oauth-basic@github.com/sofahd/api.git", token=token, networks=["log_net", nginx_api_net_name], variables=variables)
        
    def download_repo(self, folder_name_or_path: str = None) -> None:
        """
        This method overrides the download_repo method from the DockerComposeService class. It is used to download the repository for the service. 
        
        But in this case we're not only going to download the repo, but also we will save the answerset in the appropriate folder, and copy the answer html files.
        
        ---
        :param folder_name_or_path: The name of the folder to save the repo in. If None, it saves to the name of the service.
        :type folder_name_or_path: Optional[str]
        """

        super().download_repo(folder_name_or_path)

        if folder_name_or_path == None:
            folder_name_or_path = self.name


        for endpoint in self.answerset["endpoints"].keys():
            old_path = self.answerset["endpoints"][endpoint]["path"]
            self.answerset["endpoints"][endpoint]["path"] = f"/home/api/files/{self.answerset['endpoints'][endpoint]['num']}.html"
            with open(f"{folder_name_or_path}/data/files/{self.answerset['endpoints'][endpoint]['num']}.html", "wb") as f:
                f.write(open(old_path, "rb").read())

        with open(f"{folder_name_or_path}/data/answerset/answerset.json", "w") as f:
            f.write(json.dumps(self.answerset, indent=4))