from sofahutils import DockerComposeService
from typing import Optional
import json

class EnnormService(DockerComposeService):
    """
    This class implements the EnnormService class. It is a subclass of the DockerComposeService class.
    """

    def __init__(self, name:str, token:str, log_api_url:str, log_container_name:str, ip:str, placeholder_vars:dict) -> None:
        """
        Constructor for the EnnormService class.

        ---
        :param name: The name of the service.
        :type name: str
        :param token: The token to use for the github link
        :type token: str
        :param log_api_url: The url of the log api service. has to include scheme and port (e.g. http://log_api:50005)
        :type log_api_url: str
        :param log_container_name: The name of the log container to depend on.
        :type log_container_name: str
        :param ip: The ip that is in the answersets
        :type ip: str
        :param placeholder_vars: The placeholder variables for the service.
        :type placeholder_vars: dict
        """

        service_def = [
            "    container_name: <name>",
            "    build: ",
            "      context: ./<name>",
            "      args:",
            "        IP: '<ip>'",
            "        TOKEN: '<token>'",
            "        LOG_API: '<log_api_url>'",
            "    networks:",
            "      - log_net",
            "    depends_on:",
            "      <log_container_name>:",
            "        condition: service_healthy",
            "    volumes:",
            "      - ./<name>/data:/home/pro/data",
            "    environment:",
            "      - PYTHONUNBUFFERED=1"
        ]


        variables = {
            "<name>": name,
            "<ip>": ip,
            "<token>": token,
            "<log_api_url>": log_api_url,
            "<log_container_name>": log_container_name
        }

        self.placeholder_vars = placeholder_vars

        super().__init__(name=name, service_def=service_def, github_link="https://$TOKEN:x-oauth-basic@github.com/sofahd/ennorm.git", token=token, networks=["log_net"], variables=variables)



    def download_repo(self, folder_name_or_path:Optional[str]= None) -> None:
        """
        Method overwiting the superclass. And in addition to downloading the repo, also prepares the placeholders in the right path.
        
        ---
        :param folder_name_or_path: The folder name or path to download the repo to.
        :type folder_name_or_path: Optional[str]
        """
    
        super().download_repo(folder_name_or_path)

        with open(f"{folder_name_or_path}/data/conf/vars.json", "w") as file:
            file.write(json.dumps(self.placeholder_vars, indent=4))

