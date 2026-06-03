from sofahutils import DockerComposeService
import json, os


class SshHoneypotService(DockerComposeService):
    """
    Represents the SSH honeypot (`sofahd/ssh`) in a docker-compose deployment. It is a
    subclass of the DockerComposeService class.

    Like the other pots it carries the full hardening set (non-root, `cap_drop: [ALL]`,
    read-only root FS, `no-new-privileges`). The pot listens on a high, unprivileged
    in-container port and the compose maps the real cloned port to it, so -- unlike nginx --
    it needs no capabilities added back.
    """

    def __init__(self, name: str, port: int, persona: dict, log_api_url: str, log_container_name: str, token: str = None, in_port: int = 65022) -> None:
        """
        Constructor for the SshHoneypotService class.

        ---
        :param name: The name of the service.
        :type name: str
        :param port: The external port the SSH pot is published on (the cloned device's port).
        :type port: int
        :param persona: The persona dict (banner, hostname, uname, weak_credentials, ...) that
            ennorm derived from recon. Written into the cloned tree by download_repo.
        :type persona: dict
        :param log_api_url: The url of the log api service. has to include scheme and port (e.g. http://log_api:50005)
        :type log_api_url: str
        :param log_container_name: The name of the log container to depend on.
        :type log_container_name: str
        :param token: deprecated and unused; the sofahd repos are public. Kept for compatibility.
        :type token: Optional[str]
        :param in_port: The unprivileged in-container listen port, defaults to 65022.
        :type in_port: int
        """

        self.persona = persona

        service_def = [
            "    container_name: <name>",
            "    restart: unless-stopped",
            "    security_opt:",
            '      - "no-new-privileges:true"',
            "    cap_drop:",
            "      - ALL",
            # The pot writes nothing to disk (host key generated in memory, logs go to
            # log-api over HTTP); /tmp is just Python scratch, so the root FS is read-only.
            "    read_only: true",
            "    tmpfs:",
            "      - /tmp",
            "    build: ",
            "      context: ./<name>",
            "      args:",
            "        LOG_API: '<log_api>'",
            "        SSH_PORT: '<in_port>'",
            "        EXT_PORT: '<port>'",
            "    ports:",
            "      - '<port>:<in_port>'",
            "    networks:",
            "      - log_net",
            "    depends_on:",
            "      <log_container_name>:",
            "        condition: service_healthy",
            "    environment:",
            "      - PYTHONUNBUFFERED=1"
        ]

        variables = {
            "<name>": name,
            "<port>": port,
            "<in_port>": in_port,
            "<log_api>": log_api_url,
            "<log_container_name>": log_container_name
        }

        super().__init__(name=name, service_def=service_def, github_link="https://github.com/sofahd/ssh.git", token=token, networks=["log_net"], variables=variables)

    def download_repo(self, folder_name_or_path: str = None) -> None:
        """
        Overrides download_repo to also write the persona into the cloned tree, mirroring how
        ApiHoneypot writes its answerset. The pot's Dockerfile bakes ./src in, so the persona
        ends up at src/data/persona.json and is read at startup -- no runtime volume needed,
        which keeps the container's read-only root filesystem intact.

        ---
        :param folder_name_or_path: The folder to clone into. If None, uses the service name.
        :type folder_name_or_path: Optional[str]
        """

        super().download_repo(folder_name_or_path)

        if folder_name_or_path is None:
            folder_name_or_path = self.name

        persona_path = os.path.join(folder_name_or_path, "src", "data", "persona.json")
        os.makedirs(os.path.dirname(persona_path), exist_ok=True)
        with open(persona_path, "w") as handle:
            handle.write(json.dumps(self.persona, indent=4))
