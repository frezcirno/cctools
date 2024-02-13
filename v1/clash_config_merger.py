#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import copy
import logging
import os
import re
import string
import time
import traceback
from enum import Enum
from hashlib import sha1

# from multiprocessing.pool import ThreadPool
from random import choices
from typing import Dict, Iterable, List, Optional

import requests
import yaml
from pydantic import Field, model_validator
from pydantic.dataclasses import dataclass

DEFAULT_HTTP_PORT = 7890
DEFAULT_SOCKS_PORT = 7891
DEFAULT_REDIR_PORT = 7892
DEFAULT_TPROXY_PORT = 7893
DEFAULT_MIXED_PORT = 7890
DEFAULT_CONTROLLER_PORT = 9090

with open("./template.yaml") as f:
    TEMPLATE = yaml.safe_load(f)

YES_OPTIONS = {"", "y", "yes", "1", "on", "t", "true"}

DISABLE_CACHE = os.environ.get("DISABLE_CACHE", "0") in YES_OPTIONS

PRESET_CHAINS = (
    ["PROXY"]
    + list(
        {rule.split(",")[2] for rule in TEMPLATE["rules"] if rule.count(",") > 1}
        - {"DIRECT", "REJECT", "PROXY", "UDP", "FALLBACK"}
    )
    + ["UDP", "FALLBACK"]
)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"

REGEXP = re.compile(r"(\b(hk|hongkong|hong kong|tw|taiwan)\b|🇨🇳|🇭🇰|香港|台湾)", re.I)

PROXY_BLACKLIST = ["DIRECT", "REJECT", "GLOBAL", "✉️", "有效期", "群", "感谢", "非线路"]


def random_str(length=32):
    return "".join(choices(string.ascii_letters + string.digits, k=length))


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
    name: str
    urls: list[str] = Field(default_factory=list)
    ttl: int = 3600
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    def pre_root(cls, data):
        data.setdefault("tags", [])
        data["tags"].append("all")
        if "enabled" in data:
            data["enabled"] = data["enabled"] in YES_OPTIONS
            if data["enabled"]:
                data["tags"].append("default")
        data["tags"].append(data["name"])
        return data


@dataclass
class Config:
    # Proxy mode
    mode: Mode = Mode.PROXY

    # Whether to allow LAN
    trusted: bool = True

    # HTTP port
    port: Optional[int] = None

    # SOCKS5 port
    socks_port: Optional[int] = None

    # Redir port
    redir_port: Optional[int] = None

    # TProxy port
    tproxy_port: Optional[int] = None

    # HTTP and SOCKS5 mixed port
    mixed_port: Optional[int] = None

    # Clash controller port
    controller_port: int = DEFAULT_CONTROLLER_PORT

    # Clash controller secret
    secret: Optional[str] = None

    # Whether to enable DNS
    dns: Optional[bool] = None

    # DNS listen address
    dns_listen: str = "127.0.0.1"

    # DNS listen port
    dns_port: int = 53

    # DHCP interface for TUN mode
    eth: Optional[str] = None

    # Whether to keep upstream selectors
    keep_upstream_selector: bool = False

    # Custom upstreams
    group: List[str] = Field(default_factory=list)

    # Upstreams
    all_upstream: Dict[str, UpstreamSpec] = Field(default_factory=dict)

    # Custom selectors
    selector: List[str] = Field(default_factory=list)

    # Enabled upstreams
    upstream: List[str] = Field(default_factory=list)

    use_relay_rule_provider: bool = False

    @model_validator(mode="before")
    def pre_root(cls, allargs) -> dict:
        kwargs = allargs.kwargs
        if "http_port" in kwargs:
            kwargs["port"] = kwargs.pop("http_port")
        if "trust" in kwargs or "trusted" in kwargs:
            trusted = kwargs.pop("trust", None) or kwargs.pop("trusted", None)
            kwargs["trusted"] = trusted in YES_OPTIONS
        if "untrust" in kwargs or "untrusted" in kwargs:
            untrusted = kwargs.pop("untrust", None) or kwargs.pop("untrusted", None)
            kwargs["trusted"] = untrusted not in YES_OPTIONS
        if "dns" in kwargs:
            kwargs["dns"] = kwargs["dns"] in YES_OPTIONS
        if "keep_upstream_selector" in kwargs:
            kwargs["keep_upstream_selector"] = kwargs["keep_upstream_selector"] in YES_OPTIONS
        if "group" in kwargs:
            kwargs["group"] = kwargs["group"].split(",") if kwargs["group"] else []
        if "selector" in kwargs:
            kwargs["selector"] = kwargs["selector"].split(",") if kwargs["selector"] else []
        if "upstream" in kwargs:
            kwargs["upstream"] = kwargs["upstream"].split(",") if kwargs["upstream"] else ["default"]
        if "use_relay_rule_provider" in kwargs:
            kwargs["use_relay_rule_provider"] = kwargs["use_relay_rule_provider"] in YES_OPTIONS
        return allargs

    @property
    def dns_addr(self):
        return f"{self.dns_listen}:{self.dns_port}"


@dataclass(config={"arbitrary_types_allowed": True})
class UpstreamData:
    proxies: DictList
    groups: DictList

    def remove_indicator(self):
        self.proxies = self.proxies.filter(lambda proxy: all(b not in proxy["name"] for b in PROXY_BLACKLIST))

        for group in self.groups:
            group["proxies"] = [
                proxy_name for proxy_name in group["proxies"] if all(b not in proxy_name for b in PROXY_BLACKLIST)
            ]
        self.groups = self.groups.filter(lambda group: group["proxies"])


def retrieve(url: str, ttl=3600, postprocesser=None, timeout=None) -> bytes:
    save_path = "./cache/" + sha1(url.encode()).hexdigest()
    logging.info(f"Retrieving {url}, cache {save_path}")

    if os.path.exists(save_path):
        now = time.time()
        ctime = os.path.getmtime(save_path)
        if ctime > now:
            # clock changed
            logging.warn("Clock changed, ignoring cache")
        elif now - ctime < ttl:
            with open(save_path, "rb") as f:
                return f.read()

    if url.startswith("file://"):
        with open(url[7:], "rb") as f:
            content = f.read()
    else:
        resp = requests.get(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                "sec-ch-ua": '"Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            },
            timeout=timeout,
        )
        if not resp.ok:
            raise Exception("Failed to retrieve upstream")
        content = resp.content

    if postprocesser:
        content = postprocesser(content)

    if not DISABLE_CACHE:
        os.makedirs("./cache", exist_ok=True)
        with open(save_path, "wb") as f:
            f.write(content)

    return content


def retrieve_upstream(upstream: str, ttl=3600, timeout=None) -> UpstreamData:
    content = retrieve(upstream, ttl, timeout=timeout)
    obj = yaml.safe_load(content)

    proxies = DictList(obj["proxies"])
    groups = DictList(obj["proxy-groups"])

    ud = UpstreamData(proxies, groups)
    ud.remove_indicator()

    return ud


def stack_upstreams(upstreams: Iterable[UpstreamData]) -> UpstreamData:
    stacked_proxies = DictList()
    stacked_groups = DictList()

    for upstream in upstreams:
        for proxy in upstream.proxies:
            if (proxy_name := proxy["name"]) in stacked_proxies:
                # rename
                cnt = 1
                while (new_name := proxy["name"] + "+dup" + str(cnt)) in stacked_proxies:
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
            if (proxy_name := proxy["name"]) in all_proxy_names:
                # rename
                cnt = 1
                while (new_name := proxy["name"] + "+" + upstream_name) in all_proxy_names:
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
                while (new_name := group["name"] + "+" + upstream_name) in all_group_names:
                    cnt += 1
                group["name"] = new_name
            all_group_names.add(group_name)

    return upstreams


def generate(config: Config) -> Dict:
    instance = copy.deepcopy(TEMPLATE)

    if config.mode != Mode.PROXY and not config.eth:
        raise Exception("Need eth")

    if not config.all_upstream:
        raise Exception("Need upstreams")

    if config.mode != Mode.PROXY:
        if config.dns is None:
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
        if config.secret is not None:
            raise Exception("Cannot set secret in trusted mode")
        instance["secret"] = ""
    else:
        instance["allow-lan"] = False
        instance["bind-address"] = "127.0.0.1"
        instance["external-controller"] = f"127.0.0.1:{config.controller_port}"
        instance["secret"] = config.secret if config.secret is not None else random_str()

    if config.dns:
        instance["dns"]["enable"] = True
        instance["dns"]["listen"] = f"0.0.0.0:{config.dns_port}" if config.mode == Mode.REDIR else config.dns_addr
        instance["dns"]["enhanced-mode"] = "fake-ip"
        if config.mode != Mode.PROXY:
            dhcpdns = f"dhcp://{config.eth}"
            instance["dns"]["nameserver"].append(dhcpdns)
            instance["dns"]["nameserver-policy"]["+.zju.edu.cn"] = dhcpdns
    else:
        del instance["dns"]
        instance["tun"]["dns-hijack"] = []

    if config.mode == Mode.TUN:
        instance["tun"]["enable"] = True
    else:
        del instance["tun"]

    def _retrieve(key, upstream: UpstreamSpec):
        if all(tag not in config.upstream for tag in upstream.tags):
            return None
        try:
            n_urls = len(upstream.urls)
            if n_urls == 0:
                raise Exception("No urls")
            elif n_urls == 1:
                return retrieve_upstream(upstream.urls[0], upstream.ttl, timeout=10)
            else:
                # with ThreadPool(processes=min(os.cpu_count(), len(upstream.urls))) as pool:
                #     upstreams = pool.map(lambda u: retrieve_upstream(u, upstream.ttl, timeout=10), upstream.urls)
                upstreams = [retrieve_upstream(u, upstream.ttl, timeout=10) for u in upstream.urls]
                return stack_upstreams(upstreams)
        except Exception as e:
            logging.error(f"Failed to retrieve {upstream}: {e}\n{traceback.format_exc()}")
            return None

    # with ThreadPool(processes=min(os.cpu_count() or 4, len(config.upstreams))) as pool:
    #     udatas = pool.map(lambda u: _retrieve(u[0], u[1]), config.upstreams.items())
    udatas = [_retrieve(u[0], u[1]) for u in config.all_upstream.items()]

    upstream_datas: dict[str, UpstreamData] = {}
    for key, udata in zip(config.all_upstream.keys(), udatas):
        if udata is None or len(udata.proxies) == 0:
            continue
        upstream_datas[key] = udata

    upstream_datas = rename_upstreams(upstream_datas)

    instance["proxies"] = [proxy for ud in upstream_datas.values() for proxy in ud.proxies]
    instance_proxies = DictList(instance["proxies"])

    groups = []

    # all proxies
    all_proxies = {
        "name": "all",
        "type": "url-test",
        "proxies": instance_proxies.keys(),
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "tolerance": 100,
    }
    groups.append(all_proxies)

    if "cn" in config.group:
        all_proxies_cn = {
            "name": "all-cn",
            "type": "url-test",
            "proxies": [pn for pn in instance_proxies.keys() if REGEXP.search(pn)],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 100,
        }
        if all_proxies_cn["proxies"]:
            groups.append(all_proxies_cn)

    if "oversea" in config.group:
        all_proxies_oversea = {
            "name": "all-oversea",
            "type": "url-test",
            "proxies": [pn for pn in instance_proxies.keys() if REGEXP.search(pn) is None],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 100,
        }
        if all_proxies_oversea["proxies"]:
            groups.append(all_proxies_oversea)

    if "udp" in config.group:
        all_proxies_udp = {
            "name": "all-udp",
            "type": "url-test",
            "proxies": [proxy["name"] for proxy in instance_proxies if proxy.get("udp", False)],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 100,
        }
        if all_proxies_udp["proxies"]:
            groups.append(all_proxies_udp)

    # if 'udp-oversea' in config.group:
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
        groups.append(upstream_all_proxies)

        if "cn" in config.group:
            upstream_all_proxies_cn = {
                "name": key + "-cn",
                "type": "url-test",
                "proxies": [pn for pn in ud.proxies.keys() if REGEXP.search(pn)],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 100,
            }
            if upstream_all_proxies_cn["proxies"]:
                groups.append(upstream_all_proxies_cn)

        if "oversea" in config.group:
            upstream_all_proxies_oversea = {
                "name": key + "-oversea",
                "type": "url-test",
                "proxies": [pn for pn in ud.proxies.keys() if REGEXP.search(pn) is None],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 100,
            }
            if upstream_all_proxies_oversea["proxies"]:
                groups.append(upstream_all_proxies_oversea)

        if "udp" in config.group:
            upstream_all_proxies_udp = {
                "name": key + "-udp",
                "type": "url-test",
                "proxies": [proxy["name"] for proxy in ud.proxies if proxy.get("udp", False)],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 100,
            }
            if upstream_all_proxies_udp["proxies"]:
                groups.append(upstream_all_proxies_udp)

        # if 'udp-oversea' in config.group:
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

        if config.keep_upstream_selector:
            for group in ud.groups:
                if group["type"] != "url-test":
                    continue

                if set(group["proxies"]) == set(upstream_all_proxies["proxies"]):
                    continue

                group = group.copy()

                group["name"] = key + "-" + group["name"]
                groups.append(group)

    chains = []

    for selector in PRESET_CHAINS + config.selector:
        if selector == "FALLBACK":
            chains.append({"name": "FALLBACK", "type": "select", "proxies": ["PROXY", "DIRECT"]})
            continue
        chains.append(
            {
                "name": selector,
                "type": "select",
                "proxies": (["PROXY"] if selector != "PROXY" else []) + [pg["name"] for pg in groups] + ["DIRECT"],
            }
        )

    instance["proxy-groups"] = chains + groups

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
        if rules[i].startswith(b"  - "):
            rules.insert(i, b"payload:")
            break
    return b"\n".join(rules) + b"\n"


def test_parse_smoke():
    config = Config(
        {
            "mode": "tun",
            "eth": "aaa",
            "group": "cn,oversea,udp-oversea",
            "port": "12345",
            "dns": "",
            "keep_upstream_selector": 1,
            "upstream": "bbb",
        }
    )
    assert config.mode == Mode.TUN
    assert config.eth == "aaa"
    assert config.dns == True
    assert config.port == 12345
