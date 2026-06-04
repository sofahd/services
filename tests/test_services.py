"""
Tests for the services builder templates:
- the generated docker-compose is valid YAML and carries the hardening + cert args,
- ReconService writes its scan params into the right config sections (no duplicate
  [Scan], rate flows through) -- the reconciliation from the consolidation work.
"""
from ast import literal_eval
from configparser import ConfigParser
import json

import yaml

from sofahutils import DockerCompose, DockerComposeService
from services import ApiHoneypot, NginxHoneypot, PortSpoofService, LogApiService, ReconService, SshHoneypotService


def _compose_doc():
    api = ApiHoneypot(name="api_1", token="t", ext_port=49123, log_api_url="http://log_api:50005",
                      nginx_api_net_name="nginx_api_net", log_container_name="log_api", answerset={"endpoints": {}})
    ngx = NginxHoneypot(name="nginx", token="t", port=443, nginx_api_net_name="nginx_api_net",
                        nginx_config=["server {}"], api_container_name="api_1",
                        cert_pem="-----BEGIN CERTIFICATE-----\n", key_pem="-----BEGIN PRIVATE KEY-----\n")
    poof = PortSpoofService(name="poof_22", port=22, banner="OpenSSH", mode="banner", token="t",
                            log_api_url="http://log_api:50005", log_container_name="log_api")
    log = LogApiService(name="log_api", port=50005, log_folder_path="/tmp/logs", token="t")
    rec = ReconService(name="recon", token="t", log_api_url="http://log_api:50005",
                       log_container_name="log_api", endpoints={"/": {"num": 1}},
                       ip_adresses=["0.0.0.0"])
    return yaml.safe_load("\n".join(DockerCompose(services=[api, ngx, poof, log, rec]).dump()))


def test_generated_compose_is_valid_yaml():
    doc = _compose_doc()
    assert set(doc["services"]) == {"api_1", "nginx", "poof_22", "log_api", "recon"}


def test_security_opt_on_persistent_pots():
    doc = _compose_doc()
    for name in ("api_1", "nginx", "poof_22"):
        assert doc["services"][name]["security_opt"] == ["no-new-privileges:true"]


def test_cap_drop_all_on_persistent_pots():
    doc = _compose_doc()
    for name in ("api_1", "nginx", "poof_22"):
        assert doc["services"][name]["cap_drop"] == ["ALL"]


def test_nginx_re_adds_only_the_caps_it_needs():
    doc = _compose_doc()
    # nginx binds a (possibly privileged) cloned port and drops its workers from a root
    # master, so it must add exactly these back after cap_drop: [ALL] -- nothing more.
    assert doc["services"]["nginx"]["cap_add"] == ["NET_BIND_SERVICE", "CHOWN", "SETUID", "SETGID"]
    # the two non-root pots bind high ports and need nothing added back
    assert "cap_add" not in doc["services"]["api_1"]
    assert "cap_add" not in doc["services"]["poof_22"]


def test_read_only_root_fs_on_persistent_pots():
    doc = _compose_doc()
    for name in ("api_1", "nginx", "poof_22"):
        assert doc["services"][name]["read_only"] is True


def test_tmpfs_carveouts_cover_each_pot_writable_paths():
    doc = _compose_doc()
    # api renders in memory and port_spoof keeps no state -> only scratch space is writable
    assert doc["services"]["api_1"]["tmpfs"] == ["/tmp"]
    assert doc["services"]["poof_22"]["tmpfs"] == ["/tmp"]
    # nginx needs its pid, logs and proxy temp files writable -- and nothing else
    assert doc["services"]["nginx"]["tmpfs"] == ["/var/log/nginx", "/var/lib/nginx", "/run"]


def test_nginx_download_repo_writes_forged_cert(tmp_path, monkeypatch):
    # the forged PEMs land in ./ssl so the nginx image's `COPY ssl/` serves them
    monkeypatch.setattr(DockerComposeService, "download_repo", lambda self, p=None: None)
    ngx = NginxHoneypot(name="nginx", token="t", port=443, nginx_api_net_name="n",
                        nginx_config=["server {}"], api_container_name="api_1",
                        cert_pem="--CERT--", key_pem="--KEY--")
    target = tmp_path / "nginx"
    target.mkdir()
    ngx.download_repo(str(target))
    assert (target / "ssl" / "cert.pem").read_text() == "--CERT--"
    assert (target / "ssl" / "key.pem").read_text() == "--KEY--"
    assert (target / "nginx.conf").exists()


def test_nginx_without_cert_still_creates_empty_ssl_dir(tmp_path, monkeypatch):
    # a plain-HTTP pot writes no cert, but ./ssl must still exist so `COPY ssl/` succeeds
    monkeypatch.setattr(DockerComposeService, "download_repo", lambda self, p=None: None)
    ngx = NginxHoneypot(name="nginx", token="t", port=80, nginx_api_net_name="n",
                        nginx_config=["server {}"], api_container_name="api_1")
    target = tmp_path / "nginx"
    target.mkdir()
    ngx.download_repo(str(target))
    assert (target / "ssl").is_dir()
    assert not (target / "ssl" / "cert.pem").exists()


def test_recon_drops_root_and_keeps_only_net_raw():
    doc = _compose_doc()
    rec = doc["services"]["recon"]
    assert rec["cap_drop"] == ["ALL"]
    # masscan brings its own TCP/IP stack and needs raw sockets -- NET_RAW is the single
    # capability recon keeps (granted on the masscan binary via setcap in the Dockerfile).
    assert rec["cap_add"] == ["NET_RAW"]


def test_recon_root_fs_is_read_only_with_tmp_scratch():
    doc = _compose_doc()
    rec = doc["services"]["recon"]
    assert rec["read_only"] is True
    # masscan/nmap scratch files now write under /tmp, so that is the only writable path
    # outside the mounted data volume.
    assert rec["tmpfs"] == ["/tmp"]


def test_recon_omits_no_new_privileges_so_masscan_keeps_its_file_cap():
    doc = _compose_doc()
    # Unlike the persistent pots, recon must NOT set no-new-privileges: it would suppress
    # masscan's setcap NET_RAW on exec (a file cap is a privilege gain), leaving recon unable
    # to scan. This asserts the deliberate omission so it isn't "helpfully" added back later.
    assert "security_opt" not in doc["services"]["recon"]


def test_recon_writes_scan_params_into_sections(tmp_path, monkeypatch):
    # stub the git clone the base class would do
    monkeypatch.setattr(DockerComposeService, "download_repo", lambda self, p=None: None)

    data = tmp_path / "data"
    data.mkdir()
    (data / "config.ini").write_text(
        "[Masscan]\nrate = 1000\n\n[Utils]\napi_list = [\"https://api.ipify.org/\"]\n\n[Scan]\n"
    )

    rs = ReconService(name="recon", token="t", log_api_url="http://log_api:50005",
                      log_container_name="log_api", endpoints={"/": {"num": 1}},
                      ip_adresses=["0.0.0.0"], rate=5000, crawl_ports=[80], excl_ports=[])
    rs.download_repo(str(tmp_path))

    text = (data / "config.ini").read_text()
    assert text.count("[Scan]") == 1  # no duplicate section -> configparser can read it

    cfg = ConfigParser()
    cfg.read(str(data / "config.ini"))
    assert cfg.get("Masscan", "rate") == "5000"            # configurable rate flows through
    assert cfg.has_option("Utils", "api_list")             # template section preserved
    assert literal_eval(cfg.get("Scan", "ip_addresses")) == ["0.0.0.0"]
    assert literal_eval(cfg.get("Scan", "crawl_ports")) == [80]


def _ssh_service(port=2222):
    return SshHoneypotService(name="ssh_22", port=port, persona={"banner": "SSH-2.0-dropbear_2019.78"},
                              log_api_url="http://log_api:50005", log_container_name="log_api")


def _ssh_compose_doc(port=2222):
    return yaml.safe_load("\n".join(DockerCompose(services=[_ssh_service(port)]).dump()))


def test_ssh_service_is_valid_yaml_and_hardened():
    svc = _ssh_compose_doc()["services"]["ssh_22"]
    assert svc["security_opt"] == ["no-new-privileges:true"]
    assert svc["cap_drop"] == ["ALL"]
    assert svc["read_only"] is True
    assert svc["tmpfs"] == ["/tmp"]
    # the pot binds an unprivileged in-container port, so -- unlike nginx -- nothing is added back
    assert "cap_add" not in svc


def test_ssh_service_publishes_external_port_to_high_in_container_port():
    svc = _ssh_compose_doc(port=2222)["services"]["ssh_22"]
    # external 2222 -> in-container 65022 (the unprivileged listen port)
    assert svc["ports"] == ["2222:65022"]
    assert svc["build"]["args"]["SSH_PORT"] == "65022"
    assert svc["build"]["args"]["EXT_PORT"] == "2222"


def test_ssh_download_repo_writes_persona(tmp_path, monkeypatch):
    # the persona lands at src/data/persona.json so the pot's `COPY ./src` bakes it in
    monkeypatch.setattr(DockerComposeService, "download_repo", lambda self, p=None: None)
    svc = SshHoneypotService(name="ssh_22", port=2222,
                             persona={"banner": "SSH-2.0-OpenSSH_7.4", "hostname": "cam01"},
                             log_api_url="http://log_api:50005", log_container_name="log_api")
    target = tmp_path / "ssh_22"
    target.mkdir()
    svc.download_repo(str(target))

    written = json.loads((target / "src" / "data" / "persona.json").read_text())
    assert written["hostname"] == "cam01"
    assert written["banner"] == "SSH-2.0-OpenSSH_7.4"


def test_ssh_download_repo_writes_deep_clone(tmp_path, monkeypatch):
    # a credentialed recon harvest -> cloned files land in the sandbox tree and the
    # listings/commands land in captured.json, so the pot replays the real device.
    monkeypatch.setattr(DockerComposeService, "download_repo", lambda self, p=None: None)
    svc = SshHoneypotService(
        name="ssh_22", port=2222,
        persona={"banner": "SSH-2.0-dropbear_2019.78", "hostname": "cam"},
        files={"/etc/passwd": "root:x:0:0::/root:/bin/sh", "/proc/cpuinfo": "model: ARMv7"},
        listings={"/": {"raw": "drwxr-xr-x 2 root root 4096 x .", "names": ["bin", "etc"]}},
        commands={"ps": "    1 root /sbin/init"},
        log_api_url="http://log_api:50005", log_container_name="log_api")
    target = tmp_path / "ssh_22"
    target.mkdir()
    svc.download_repo(str(target))

    data_dir = target / "src" / "data"
    assert (data_dir / "sandbox" / "etc" / "passwd").read_text().startswith("root:")
    assert (data_dir / "sandbox" / "proc" / "cpuinfo").read_text() == "model: ARMv7"
    captured = json.loads((data_dir / "captured.json").read_text())
    assert captured["listings"]["/"]["names"] == ["bin", "etc"]
    assert captured["commands"]["ps"].endswith("/sbin/init")


def test_ssh_download_repo_without_harvest_writes_empty_captured(tmp_path, monkeypatch):
    # no credentials -> empty captured.json and no sandbox overrides; pot uses its defaults.
    monkeypatch.setattr(DockerComposeService, "download_repo", lambda self, p=None: None)
    target = tmp_path / "ssh_22"
    target.mkdir()
    _ssh_service().download_repo(str(target))

    captured = json.loads((target / "src" / "data" / "captured.json").read_text())
    assert captured == {"listings": {}, "commands": {}}
    assert not (target / "src" / "data" / "sandbox").exists()


def test_recon_writes_ssh_credentials_when_provided(tmp_path, monkeypatch):
    monkeypatch.setattr(DockerComposeService, "download_repo", lambda self, p=None: None)
    data = tmp_path / "data"
    data.mkdir()
    (data / "config.ini").write_text("[Masscan]\nrate = 1000\n\n[Scan]\n")

    rs = ReconService(name="recon", token="t", log_api_url="http://log_api:50005",
                      log_container_name="log_api", endpoints={"/": {"num": 1}},
                      ip_adresses=["0.0.0.0"], ssh_username="root", ssh_password="root")
    rs.download_repo(str(tmp_path))

    cfg = ConfigParser()
    cfg.read(str(data / "config.ini"))
    assert cfg.get("Ssh", "username") == "root"
    assert cfg.get("Ssh", "password") == "root"
    assert cfg.getboolean("Ssh", "enabled") is True


def test_recon_omits_ssh_section_without_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(DockerComposeService, "download_repo", lambda self, p=None: None)
    data = tmp_path / "data"
    data.mkdir()
    (data / "config.ini").write_text("[Masscan]\nrate = 1000\n\n[Scan]\n")

    rs = ReconService(name="recon", token="t", log_api_url="http://log_api:50005",
                      log_container_name="log_api", endpoints={"/": {"num": 1}},
                      ip_adresses=["0.0.0.0"])
    rs.download_repo(str(tmp_path))

    cfg = ConfigParser()
    cfg.read(str(data / "config.ini"))
    assert not cfg.has_section("Ssh")
