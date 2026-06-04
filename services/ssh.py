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

    def __init__(self, name: str, port: int, persona: dict, log_api_url: str, log_container_name: str, token: str = None, in_port: int = 65022, files: dict = None, listings: dict = None, commands: dict = None) -> None:
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
        :param files: Optional ``{path: content}`` of files recon cloned from the real device
            (deep harvest). Written into the pot's sandbox so ``cat`` serves the real content.
        :type files: Optional[dict]
        :param listings: Optional ``{dir: {"raw", "names"}}`` directory listings cloned from the
            device, replayed by the pot's ``ls``.
        :type listings: Optional[dict]
        :param commands: Optional ``{name: output}`` command outputs cloned from the device
            (ps, ifconfig, ...), replayed verbatim by the pot.
        :type commands: Optional[dict]
        """

        self.persona = persona
        self.files = files or {}
        self.listings = listings or {}
        self.commands = commands or {}

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

        data_dir = os.path.join(folder_name_or_path, "src", "data")
        os.makedirs(data_dir, exist_ok=True)

        with open(os.path.join(data_dir, "persona.json"), "w") as handle:
            handle.write(json.dumps(self.persona, indent=4))

        # Deep-harvest material (empty unless recon had credentials):
        #  * cloned files are planted into the sandbox tree the pot's fake FS loads, so `cat`
        #    serves the real device's content (and overrides the shipped decoys);
        #  * listings + command outputs go to captured.json, which the pot replays for
        #    `ls` / `ps` / `ifconfig` / ...
        self._write_sandbox_files(os.path.join(data_dir, "sandbox"))
        with open(os.path.join(data_dir, "captured.json"), "w") as handle:
            handle.write(json.dumps({"listings": self.listings, "commands": self.commands}, indent=4))

    def _write_sandbox_files(self, sandbox_dir: str) -> None:
        """
        Plant each cloned ``{path: content}`` file under ``sandbox_dir`` at its device path.

        ``..`` / ``.`` segments are dropped so a hostile harvested path can never escape the
        sandbox directory -- the same defensive join the api pot uses for its file-read
        emulation.

        ---
        :param sandbox_dir: The pot's ``src/data/sandbox`` directory.
        :type sandbox_dir: str
        """

        for path, content in self.files.items():
            parts = [segment for segment in str(path).split("/") if segment not in ("", ".", "..")]
            if not parts:
                continue
            target = os.path.join(sandbox_dir, *parts)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "w") as handle:
                handle.write(content if isinstance(content, str) else str(content))
