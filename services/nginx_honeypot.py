from sofahutils import DockerComposeService
from typing import Optional

class NginxHoneypot(DockerComposeService):
    """
    This class represents the Nginx docker-compose service for the honeypot. It inherits from the DockerComposeService
    """

    def __init__(self, name:str, token:str, port:int, nginx_api_net_name:str, nginx_config:list[str], api_container_name:str) -> None:
        """
        Constructor for the NginxHoneypotService class.

        ---
        :param name: The name of the service.
        :type name: str
        :param token: The token to use for the github link.
        :type token: str
        :param port: The port to run the service on.
        :type port: int
        :param nginx_api_net_name: The name of the network to attach the service to.
        :type nginx_api_net_name: str
        :param nginx_config: The configuration file content for the nginx service.
        :type nginx_config: list[str]
        """
        
        self.nginx_config = nginx_config

        service_def = [
            "    container_name: <name>",
            "    restart: unless-stopped",
            "    build: ",
            "      context: ./<name>",
            "    networks:",
            "      - log_net",
            "      - <nginx_api_net_name>",
            "    ports:",
            "      - '<port>:<port>'",
            "    depends_on:",
            "      - <api_container_name>",
        ]

        variables = {
            "<name>": name,
            "<port>": port,
            "<nginx_api_net_name>": nginx_api_net_name,
            "<api_container_name>": api_container_name
        }

        super().__init__(name=name, service_def=service_def, github_link="https://$TOKEN:x-oauth-basic@github.com/sofahd/nginx.git", token=token, networks=["log_net", nginx_api_net_name], variables=variables)


    def download_repo(self, folder_name_or_path:Optional[str] = None) -> None:
        """
        This method overrides the download_repo method from the DockerComposeService class. It is used to download the repository for the service. 
        
        But this overriding method doesn't only download the repo, but goes ahead and saves the nginx.conf in the appropriate folder.

        ---
        :param folder_name_or_path: The name of the folder to save the repo in. If None, it saves it in the current directory.
        :type folder_name_or_path: Optional[str]
        """

        super().download_repo(folder_name_or_path)

        if folder_name_or_path == None:
            folder_name_or_path = self.name

        with open(f"{folder_name_or_path}/nginx.conf", "w") as f:
            for line in self.nginx_config:
                f.write(line + "\n")
            
        return