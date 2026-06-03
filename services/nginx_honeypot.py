from sofahutils import DockerComposeService
from typing import Optional
import os

class NginxHoneypot(DockerComposeService):
    """
    This class represents the Nginx docker-compose service for the honeypot. It inherits from the DockerComposeService
    """

    def __init__(self, name:str, token:str, port:int, nginx_api_net_name:str, nginx_config:list[str], api_container_name:str, cert_pem:str="", key_pem:str="") -> None:
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
        :param api_container_name: The name of the container to depend on.
        :type api_container_name: str
        :param cert_pem: PEM-encoded TLS certificate to serve, forged by ennorm's cert_forge from
            the cloned device's captured cert. Empty for a plain-HTTP pot.
        :type cert_pem: str
        :param key_pem: PEM-encoded private key matching ``cert_pem``. Empty for a plain-HTTP pot.
        :type key_pem: str
        """

        self.nginx_config = nginx_config
        self.cert_pem = cert_pem
        self.key_pem = key_pem

        service_def = [
            "    container_name: <name>",
            "    restart: unless-stopped",
            "    security_opt:",
            '      - "no-new-privileges:true"',
            "    cap_drop:",
            "      - ALL",
            # nginx master runs as root, binds the (possibly privileged) cloned port and
            # drops its workers to www-data, so it needs exactly these back -- nothing else.
            "    cap_add:",
            "      - NET_BIND_SERVICE",
            "      - CHOWN",
            "      - SETUID",
            "      - SETGID",
            # Read-only root FS; nginx only needs its pid, logs and proxy temp files
            # writable, so carve those out as tmpfs and nothing else.
            "    read_only: true",
            "    tmpfs:",
            "      - /var/log/nginx",
            "      - /var/lib/nginx",
            "      - /run",
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
            "<api_container_name>": api_container_name,
        }

        super().__init__(name=name, service_def=service_def, github_link="https://github.com/sofahd/nginx.git", token=token, networks=["log_net", nginx_api_net_name], variables=variables)


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

        # The nginx image always COPYs ./ssl/ into /etc/nginx/ssl. For a TLS pot, drop the
        # forged cert/key there so nginx can serve them (nginx.conf points ssl_certificate at
        # these paths); for a plain-HTTP pot the dir stays empty. Either way it must exist so
        # the image's COPY succeeds.
        ssl_dir = f"{folder_name_or_path}/ssl"
        os.makedirs(ssl_dir, exist_ok=True)
        if self.cert_pem and self.key_pem:
            with open(f"{ssl_dir}/cert.pem", "w") as f:
                f.write(self.cert_pem)
            with open(f"{ssl_dir}/key.pem", "w") as f:
                f.write(self.key_pem)

        return