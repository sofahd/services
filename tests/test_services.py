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
                        create_cert="true", cn="device.local", o="ACME")
    poof = PortSpoofService(name="poof_22", port=22, banner="OpenSSH", mode="banner", token="t",
                            log_api_url="http://log_api:50005", log_container_name="log_api")
    log = LogApiService(name="log_api", port=50005, log_folder_path="/tmp/logs", token="t")
    return yaml.safe_load("\n".join(DockerCompose(services=[api, ngx, poof, log]).dump()))


def test_generated_compose_is_valid_yaml():
    doc = _compose_doc()
    assert set(doc["services"]) == {"api_1", "nginx", "poof_22", "log_api"}


def test_security_opt_on_persistent_pots():
    doc = _compose_doc()
    for name in ("api_1", "nginx", "poof_22"):
        assert doc["services"][name]["security_opt"] == ["no-new-privileges:true"]


def test_nginx_carries_self_signed_cert_args():
    doc = _compose_doc()
    args = doc["services"]["nginx"]["build"]["args"]
    assert args["CREATE_CERT"] == "true"
    assert args["CN"] == "device.local"
    assert args["O"] == "ACME"


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
