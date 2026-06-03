"""
Tests for the services builder templates:
- the generated docker-compose is valid YAML and carries the hardening + cert args,
- ReconService writes its scan params into the right config sections (no duplicate
  [Scan], rate flows through) -- the reconciliation from the consolidation work.
"""
from ast import literal_eval
from configparser import ConfigParser

import yaml

from sofahutils import DockerCompose, DockerComposeService
from services import ApiHoneypot, NginxHoneypot, PortSpoofService, LogApiService, ReconService


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
