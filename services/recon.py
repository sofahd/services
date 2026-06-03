from sofahutils import DockerComposeService
from typing import Optional, Union
from configparser import ConfigParser
import json


class ReconService(DockerComposeService):
    """
    This class is built to represent the recon service. It is a subclass of the DockerComposeService class.
    """
    
    def __init__(self, name:str, token:str, log_api_url:str, log_container_name:str, endpoints:dict, ip_adresses:list[str], rate:Optional[int] = 1000, crawl_ports:Optional[Union[list[int],int]] = None,
             excl_ports:Optional[Union[int, list[int]]] = None) -> None:
        """
        Constructor for the ReconService class. It takes in the name of the service

        ---
        :param name: The name of the service.
        :type name: str
        :param token: The token to use for the github link.
        :type token: str
        :param endpoints: The endpoints to scan.
        :type endpoints: dict
        :param ip_adresses: The ip adresses to scan.
        :type ip_adresses: list[str]
        :param rate: The rate at which to scan the endpoints with masscan. (default is 1000)
        :type rate: Optional[int]
        :param crawl_ports: Ports you specifically want to crawl.
        :type crawl_ports: Optional[Union[list[int],int]]
        :param excl_ports: Ports you specifically want to exclude.
        :type excl_ports: Optional[Union[int, list[int]]]
        :param log_api_url: The url of the log api service. has to include scheme and port (e.g. http://log_api:50005)
        :type log_api_url: str
        :param log_container_name: The name of the log container to depend on.
        :type log_container_name: str
        """

        service_def = [
            "    container_name: <name>",
            # Hardened like the persistent pots, with two recon-specific differences:
            # (1) cap_add NET_RAW -- masscan brings its own TCP/IP stack and needs raw sockets.
            #     The Dockerfile grants the cap on the masscan binary via setcap, which only
            #     takes effect while NET_RAW stays in the container's bounding set, hence
            #     cap_add here on top of cap_drop: [ALL]. nmap needs nothing (connect scan).
            # (2) NO no-new-privileges -- it suppresses file capabilities on exec (they are a
            #     privilege gain, exactly what the flag blocks), which would leave masscan
            #     unable to scan. recon is a short-lived one-shot job, not a long-running pot.
            "    cap_drop:",
            "      - ALL",
            "    cap_add:",
            "      - NET_RAW",
            "    read_only: true",
            "    tmpfs:",
            "      - /tmp",
            "    build: ",
            "      context: ./<name>",
            "      args:",
            "        LOG_API: '<log_api>'",
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
            "<token>": token,
            "<log_api>": log_api_url,
            "<log_container_name>": log_container_name
        }

        self.endpoints = endpoints
        self.ip_adresses = ip_adresses if isinstance(ip_adresses, list) else [ip_adresses]
        self.crawl_ports = crawl_ports if isinstance(crawl_ports, list) else [crawl_ports] if crawl_ports != None else []
        self.excl_ports = excl_ports if isinstance(excl_ports, list) else [excl_ports] if excl_ports != None else []
        self.rate = rate

        super().__init__(name=name, service_def=service_def, github_link="https://github.com/sofahd/recon.git", token=token, networks=["log_net"], variables=variables)



    def download_repo(self, folder_name_or_path:Optional[str] = None) -> None:
        """
        This method overrides the download_repo method from the DockerComposeService class.
        We do this, to ensurer that the endpoints and other variables are saved properly.

        ---
        :param folder_name_or_path: The name of the folder to save the repo in. If None, it saves it in the current directory.
        :type folder_name_or_path: Optional[str]
        """
        
        super().download_repo(folder_name_or_path)

        if folder_name_or_path == None:
            folder_name_or_path = self.name

        with open(f"{folder_name_or_path}/data/endpoints.json", "w") as f:
            f.write(json.dumps(self.endpoints, indent=4))

        # Set the masscan rate and scan parameters in their proper sections via
        # configparser. A blind append would duplicate the [Scan] section that the
        # recon repo's config.ini template already ships, which configparser then
        # refuses to read (DuplicateSectionError).
        config_path = f"{folder_name_or_path}/data/config.ini"
        config = ConfigParser()
        config.read(config_path)
        if not config.has_section("Masscan"):
            config.add_section("Masscan")
        config.set("Masscan", "rate", str(self.rate))
        if not config.has_section("Scan"):
            config.add_section("Scan")
        config.set("Scan", "ip_addresses", str(self.ip_adresses))
        config.set("Scan", "crawl_ports", str(self.crawl_ports))
        config.set("Scan", "excl_ports", str(self.excl_ports))
        with open(config_path, "w") as f:
            config.write(f)