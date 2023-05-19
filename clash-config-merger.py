#!/usr/bin/env python3
import copy
import logging
import os
import re
import string
import time
import traceback
from enum import Enum
from hashlib import sha1
from multiprocessing.pool import ThreadPool
from random import choices
from typing import Dict, Iterable, List, Optional

import requests
import yaml
from pydantic import Field
from pydantic.dataclasses import dataclass

logging.basicConfig(
    level=logging.INFO,
    filename="clash-config-merger.log",
    format="%(asctime)s.%(msecs)d %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

DEFAULT_HTTP_PORT = 7890
DEFAULT_SOCKS_PORT = 7891
DEFAULT_REDIR_PORT = 7892
DEFAULT_TPROXY_PORT = 7893
DEFAULT_MIXED_PORT = 7890
DEFAULT_CONTROLLER_PORT = 9090

with open("./template.yaml") as f:
    TEMPLATE = yaml.safe_load(f)

PRESET_CHAINS = ["PROXY", "PROXY-UDP"] + list({rule.split(",")[2] for rule in TEMPLATE["rules"]
                                              if rule.count(",") > 1} - {"DIRECT", "REJECT", "PROXY", "PROXY-UDP"})

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"

REGEXP = re.compile(r"(\b(HK|hongkong|TW|taiwan)\b|🇨🇳|🇭🇰|香港|台湾)", re.I)

PROXY_BLACKLIST = ["DIRECT", "REJECT", "GLOBAL", "✉️", "有效期", "群", "感谢", "非线路"]


class DictList(list):
    """
    A list that can be accessed by key
    """

    def __getitem__(self, item):
        if isinstance(item, str):
            for i in self:
                if i["name"] == item:
                    return i
            raise KeyError(item)
        return super().__getitem__(item)

    def __setitem__(self, key, value):
        if isinstance(key, str):
            for i in self:
                if i["name"] == key:
                    i.update(value)
            else:
                self.append(value)
        else:
            return super().__setitem__(key, value)

    def __add__(self, other):
        return DictList(super().__add__(other))

    def __contains__(self, __key: object) -> bool:
        return super().__contains__(__key) or any(i["name"] == __key for i in self)

    def keys(self):
        return [i["name"] for i in self]

    def filter(self, func):
        return DictList(i for i in self if func(i))


class Mode(str, Enum):
    PROXY = "proxy"
    TUN = "tun"
    REDIR = "redir"


@dataclass
class UpstreamSpec:
    urls: list[str] = Field(default_factory=list)
    ttl: int = 3600
    enabled: bool = True


@dataclass
class Config:
    mode: Mode = Mode.PROXY
    trusted: bool = True

    port: Optional[int] = None
    socks_port: Optional[int] = None
    redir_port: Optional[int] = None
    tproxy_port: Optional[int] = None
    mixed_port: Optional[int] = None

    controller_port: int = DEFAULT_CONTROLLER_PORT
    secret: Optional[str] = None

    fake_ip: bool = True  # deprecated

    dns: bool = False
    eth: Optional[str] = None

    keep_upstream_chains: bool = False
    custom_groups: List[str] = Field(default_factory=list)

    upstreams: Dict[str, UpstreamSpec] = Field(default_factory=dict)
    custom_chains: List[str] = Field(default_factory=list)

    secret_upstreams: List[str] = Field(default_factory=list)

    @staticmethod
    def from_dict(data: dict):
        if 'http_port' in data:
            data['port'] = data.pop('http_port')
        return Config(**data)

    def __post_init__(self):
        if self.trusted == '':
            self.trusted = True
        if self.dns == '':
            self.dns = True
        if self.keep_upstream_chains == '':
            self.keep_upstream_chains = True
        if isinstance(self.custom_groups, str):
            self.custom_groups = self.custom_groups.split(",") if self.custom_groups else []
        if isinstance(self.secret_upstreams, str):
            self.secret_upstreams = self.secret_upstreams.split(",") if self.secret_upstreams else []

    def __post_init_post_parse__(self):
        pass


@dataclass
class UpstreamData:
    proxies: DictList
    groups: DictList

    def __post_init__(self):
        self.proxies = DictList(self.proxies)
        self.groups = DictList(self.groups)

    def remove_indicator(self):
        self.proxies = self.proxies.filter(lambda proxy: all(b not in proxy["name"] for b in PROXY_BLACKLIST))

        for group in self.groups:
            group["proxies"] = [proxy_name for proxy_name in group["proxies"]
                                if all(b not in proxy_name for b in PROXY_BLACKLIST)]
        self.groups = self.groups.filter(lambda group: group["proxies"])


def retrieve(url: str, ttl=3600, mutator=None, timeout=None) -> bytes:
    logging.info(f"Retrieving {url}")

    save_path = "./cache/" + sha1(url.encode()).hexdigest()

    if os.path.exists(save_path):
        now = time.time()
        ctime = os.path.getmtime(save_path)
        if ctime > now:
            # clock changed
            logging.warn("Clock changed, ignoring cache")
        elif now - ctime < ttl:
            with open(save_path, "rb") as f:
                return f.read()

    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
    if not resp.ok:
        raise Exception("Failed to retrieve upstream")

    content = resp.content
    if mutator:
        content = mutator(content)

    os.makedirs("./cache", exist_ok=True)
    with open(save_path, "wb") as f:
        f.write(content)

    return content


def retrieve_upstream(upstream: str, ttl=3600, timeout=None) -> UpstreamData:
    content = retrieve(upstream, ttl, timeout=timeout)
    obj = yaml.safe_load(content)

    proxies = obj["proxies"]
    groups = obj["proxy-groups"]

    ud = UpstreamData(proxies, groups)
    ud.remove_indicator()

    return ud


def stack_upstreams(upstreams: Iterable[UpstreamData]) -> UpstreamData:
    stacked_proxies = DictList()
    stacked_groups = DictList()

    for upstream in upstreams:
        for proxy in upstream.proxies:
            if (proxy_name := proxy['name']) in stacked_proxies:
                # rename
                cnt = 1
                while (new_name := proxy["name"] + '+dup' + str(cnt)) in stacked_proxies:
                    cnt += 1
                proxy["name"] = new_name
                for group in upstream.groups:
                    group["proxies"] = [new_name if cp == proxy_name else cp for cp in group["proxies"]]
            stacked_proxies.append(proxy)

        for group in upstream.groups:
            if (group_name := group["name"]) in stacked_groups:
                stacked_groups[group_name]["proxies"] += group["proxies"]
            else:
                stacked_groups[group_name] = group

    return UpstreamData(stacked_proxies, stacked_groups)


def rename_upstreams(upstreams: dict[str, UpstreamData]) -> dict[str, UpstreamData]:

    # check proxy name conflict
    all_proxy_names = set()
    for upstream_name, upstream in upstreams.items():
        for proxy in upstream.proxies:
            if (proxy_name := proxy['name']) in all_proxy_names:
                # rename
                cnt = 1
                while (new_name := proxy["name"] + '+' + upstream_name) in all_proxy_names:
                    cnt += 1
                proxy["name"] = new_name
                for group in upstream.groups:
                    group["proxies"] = [new_name if cp == proxy_name else cp for cp in group["proxies"]]
            all_proxy_names.add(proxy_name)

    # check group name conflict
    all_group_names = set()
    for upstream_name, upstream in upstreams.items():
        for group in upstream.groups:
            if (group_name := group["name"]) in all_group_names:
                # rename
                cnt = 1
                while (new_name := group["name"] + '+' + upstream_name) in all_group_names:
                    cnt += 1
                group["name"] = new_name
            all_group_names.add(group_name)

    return upstreams


def generate(config: Config) -> Dict:
    instance = copy.deepcopy(TEMPLATE)

    if config.mode != Mode.PROXY and not config.eth:
        raise Exception("Need eth")

    if not config.upstreams:
        raise Exception("Need upstreams")

    if config.mode != Mode.PROXY:
        config.dns = True
        config.trusted = True

    # set ports
    if config.mode == Mode.PROXY:
        if not config.mixed_port:
            config.port = config.port or DEFAULT_HTTP_PORT
            config.socks_port = config.socks_port or DEFAULT_SOCKS_PORT
    elif config.mode == Mode.REDIR:
        config.redir_port = config.redir_port or DEFAULT_REDIR_PORT
        config.tproxy_port = config.tproxy_port or DEFAULT_TPROXY_PORT

    if config.port:
        instance["port"] = config.port
    if config.socks_port:
        instance["socks-port"] = config.socks_port
    if config.mixed_port:
        instance["mixed-port"] = config.mixed_port
    if config.redir_port:
        instance["redir-port"] = config.redir_port
    if config.tproxy_port:
        instance["tproxy-port"] = config.tproxy_port

    if config.trusted:
        instance["allow-lan"] = True
        instance["bind-address"] = "*"
        instance["external-controller"] = f"127.0.0.1:{config.controller_port}"
        instance["secret"] = ""
    else:
        instance["allow-lan"] = False
        instance["bind-address"] = "127.0.0.1"
        instance["external-controller"] = f"127.0.0.1:{config.controller_port}"
        instance["secret"] = config.secret if config.secret is not None else ''.join(choices(string.ascii_letters + string.digits, k=32))

    if config.dns:
        instance["dns"]["enable"] = True
        instance["dns"]["listen"] = "0.0.0.0:53" if config.mode == Mode.REDIR else "127.0.0.53:53"
        instance["dns"]["enhanced-mode"] = "fake-ip"
        if config.mode != Mode.PROXY:
            instance["dns"]["nameserver"].append(f"dhcp://{config.eth}")
    else:
        del instance["dns"]

    if config.mode == Mode.TUN:
        instance["tun"]["enable"] = True
    else:
        del instance["tun"]

    def _retrieve(key, upstream: UpstreamSpec):
        if not upstream.enabled and key not in config.secret_upstreams:
            return None
        try:
            n_urls = len(upstream.urls)
            if n_urls == 0:
                raise Exception("No urls")
            elif n_urls == 1:
                return retrieve_upstream(upstream.urls[0], upstream.ttl, timeout=10)
            else:
                with ThreadPool(processes=min(os.cpu_count(), len(upstream.urls))) as pool:
                    upstreams = pool.map(lambda u: retrieve_upstream(u, upstream.ttl, timeout=10), upstream.urls)
                return stack_upstreams(upstreams)
        except Exception as e:
            logging.error(f"Failed to retrieve {upstream}: {e}\n{traceback.format_exc()}")
            return None

    with ThreadPool(processes=min(os.cpu_count() or 4, len(config.upstreams))) as pool:
        udatas = pool.map(lambda u: _retrieve(u[0], u[1]), config.upstreams.items())

    upstream_datas: dict[str, UpstreamData] = {}
    for key, udata in zip(config.upstreams.keys(), udatas):
        if udata is None:
            continue
        upstream_datas[key] = udata

    upstream_datas = rename_upstreams(upstream_datas)

    instance["proxies"] = [proxy for ud in upstream_datas.values() for proxy in ud.proxies]
    instance_proxies = DictList(instance["proxies"])

    proxy_groups = []

    # all proxies
    all_proxies = {
        "name": "all",
        "type": "url-test",
        "proxies": instance_proxies.keys(),
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 100,
    }
    proxy_groups.append(all_proxies)

    if 'cn' in config.custom_groups:
        all_proxies_cn = {
            "name": "all-cn",
            "type": "url-test",
            "proxies": [pn for pn in instance_proxies.keys() if REGEXP.search(pn)],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 100,
        }
        if all_proxies_cn["proxies"]:
            proxy_groups.append(all_proxies_cn)

    if 'oversea' in config.custom_groups:
        all_proxies_oversea = {
            "name": "all-oversea",
            "type": "url-test",
            "proxies": [pn for pn in instance_proxies.keys() if REGEXP.search(pn) is None],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 100,
        }
        if all_proxies_oversea["proxies"]:
            proxy_groups.append(all_proxies_oversea)

    if 'udp' in config.custom_groups:
        all_proxies_udp = {
            "name": "all-udp",
            "type": "url-test",
            "proxies": [proxy["name"] for proxy in instance_proxies if proxy.get("udp", False)],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 100,
        }
        if all_proxies_udp["proxies"]:
            proxy_groups.append(all_proxies_udp)

    # if 'udp-oversea' in config.custom_groups:
    #     all_proxies_udp_oversea = {
    #         "name": "all-udp-oversea",
    #         "type": "url-test",
    #         "proxies": [proxy["name"] for proxy in instance_proxies if proxy.get("udp", False) and REGEXP.search(proxy["name"]) is None],
    #         "url": "http://www.gstatic.com/generate_204",
    #         "interval": 300,
    #         "tolerance": 100,
    #     }
    #     if all_proxies_udp_oversea["proxies"]:
    #         proxy_groups.append(all_proxies_udp_oversea)

    # upstream proxies invidually
    for key, ud in upstream_datas.items():
        upstream_all_proxies = {
            "name": key,
            "type": "url-test",
            "proxies": ud.proxies.keys(),
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 100,
        }
        proxy_groups.append(upstream_all_proxies)

        if 'cn' in config.custom_groups:
            upstream_all_proxies_cn = {
                "name": key + "-cn",
                "type": "url-test",
                "proxies": [pn for pn in ud.proxies.keys() if REGEXP.search(pn)],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 100,
            }
            if upstream_all_proxies_cn["proxies"]:
                proxy_groups.append(upstream_all_proxies_cn)

        if 'oversea' in config.custom_groups:
            upstream_all_proxies_oversea = {
                "name": key + "-oversea",
                "type": "url-test",
                "proxies": [pn for pn in ud.proxies.keys() if REGEXP.search(pn) is None],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 100,
            }
            if upstream_all_proxies_oversea["proxies"]:
                proxy_groups.append(upstream_all_proxies_oversea)

        if 'udp' in config.custom_groups:
            upstream_all_proxies_udp = {
                "name": key + "-udp",
                "type": "url-test",
                "proxies": [proxy["name"] for proxy in ud.proxies if proxy.get("udp", False)],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 100,
            }
            if upstream_all_proxies_udp["proxies"]:
                proxy_groups.append(upstream_all_proxies_udp)

        # if 'udp-oversea' in config.custom_groups:
        #     upstream_all_proxies_udp_oversea = {
        #         "name": key + "-udp-oversea",
        #         "type": "url-test",
        #         "proxies": [proxy["name"] for proxy in proxies if proxy.get("udp", False) and REGEXP.search(proxy["name"]) is None],
        #         "url": "http://www.gstatic.com/generate_204",
        #         "interval": 300,
        #         "tolerance": 100,
        #     }
        #     if upstream_all_proxies_udp_oversea["proxies"]:
        #         proxy_groups.append(upstream_all_proxies_udp_oversea)

        if config.keep_upstream_chains:
            for group in ud.groups:
                if group["type"] != "url-test":
                    continue

                if set(group["proxies"]) == set(upstream_all_proxies["proxies"]):
                    continue

                group = group.copy()

                group["name"] = key + "-" + group["name"]
                proxy_groups.append(group)

    chain_groups = []

    for custom_chain in PRESET_CHAINS + config.custom_chains:
        group = {
            "name": custom_chain,
            "type": "select",
            "proxies": (["PROXY"] if custom_chain != "PROXY" else []) + ["DIRECT"] + [pg["name"] for pg in proxy_groups]
        }
        if "direct" in config.custom_groups:
            group["proxies"].append("DIRECT")
        chain_groups.append(group)

    instance["proxy-groups"] = chain_groups + proxy_groups

    return instance


def convert_raw_list_to_rule_provider(raw_list: bytes) -> bytes:
    rules = []
    for l in raw_list.splitlines():
        l = l.strip()
        if not l or l.startswith(b"#"):
            rules.append(l)
        else:
            rules.append(b"  - " + l)
    for i in range(len(rules)):
        if rules[i].startswith(b'  - '):
            rules.insert(i, b"payload:")
            break
    return b"\n".join(rules) + b"\n"


def test_parse_smoke():
    config = Config.from_dict({
        "mode": "tun",
        "eth": "aaa",
        "custom_groups": "cn,oversea,udp-oversea",
        "port": '12345',
        "dns": '',
        "keep_upstream_chains": 1,
        "secret_upstreams": "bbb",
    })
    assert config.mode == Mode.TUN
    assert config.eth == "aaa"
    assert config.dns == True
    assert config.port == 12345


if __name__ == "__main__":
    import sys
    logging.info(f"Python version: {sys.version}")
    bind = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

    from flask import Flask, Response, request, url_for
    app = Flask(__name__)

    @app.get("/clash/config.yaml")
    def generate_yaml():
        args = request.values.to_dict()
        if "upstreams" not in args:
            with open("upstreams.yaml") as f:
                args["upstreams"] = yaml.safe_load(f)
        client_ip = request.headers.get("X-Real-IP", request.remote_addr)
        logging.info(f"{client_ip} {args}")
        try:
            config = Config.from_dict(args)
            clash_config = generate(config)
            for rp, value in clash_config["rule-providers"].items():
                value["url"] = url_for("forward", key=rp, _external=True, _scheme="http")
            stream = yaml.safe_dump(clash_config, allow_unicode=True, sort_keys=False)
        except Exception as e:
            logging.error(f"Generate config failed: {e}\n{traceback.format_exc()}")
            return str(e), 500
        return Response(stream, content_type="text/yaml; charset=utf-8")

    @app.get("/clash/forward")
    def forward():
        key = request.values.get("key")
        if key not in TEMPLATE["rule-providers"]:
            return "Not found", 404
        url = TEMPLATE["rule-providers"][key]["url"]
        if url.startswith("raw://"):
            return retrieve(url[6:], 86400, convert_raw_list_to_rule_provider), 200, {"Content-Type": "text/yaml; charset=utf-8"}
        return retrieve(url, 86400), 200, {"Content-Type": "text/yaml; charset=utf-8"}

    from gevent.pywsgi import WSGIServer
    http_server = WSGIServer((bind, port), app)
    http_server.serve_forever()
