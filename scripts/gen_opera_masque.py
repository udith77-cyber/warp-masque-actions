#!/usr/bin/env python3
"""生成 Opera VPN over Cloudflare WARP(MASQUE) 的 mihomo 配置。

链路: 本机 -> MASQUE 接入点 -> Opera 落地 -> 目标

每个 Opera 落地和每个 MASQUE 接入点都组合一遍，任一环失效都有替代路径。
MASQUE 那一跳把 Opera 的地址完全藏进 QUIC 隧道，本机侧只看得到
162.159.198.x 这类 Cloudflare 地址。

用法:
    python3 gen.py <usque-config.json> <opera-proxy 路径> <输出目录>
"""
import json
import os
import re
import subprocess
import sys

# MASQUE 接入点。均经真机握手实测（2026-09-05，psg2）：
# QUIC 回包不等于能建隧道，162.159.194/196/197/204 与 v6 的 102/105 段
# 会回包但 login 失败，不要往回加。
V4 = ["162.159.198.1", "162.159.198.2", "162.159.199.1", "162.159.199.2"]
V6 = ["2606:4700:103::1", "2606:4700:103::2",
      "2606:4700:104::1", "2606:4700:104::2"]
# 4443/8095 是后来补测出来的，实测 8/8 全通
PORTS = (443, 500, 1701, 4500, 4443, 8443, 8095)

# CF 没有 A 记录指向 MASQUE 段，官方域名只能用在 SNI 上
OFFICIAL_SNI = "zt-masque.cloudflareclient.com"
SNI_NODE = ("162.159.198.1", 443)

# Opera VPN 只有三个大区，没有国家级选项
REGIONS = {"AS": "亚洲", "EU": "欧洲", "AM": "美洲"}

RS = "https://raw.githubusercontent.com"
RULESETS = [
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/UnBan.list"),
    ("🛑 全球拦截", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/BanAD.list"),
    ("🍃 应用净化", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list"),
    ("📢 谷歌FCM", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/GoogleFCM.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/GoogleCN.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/SteamCN.list"),
    ("Ⓜ️ 微软服务", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Microsoft.list"),
    ("🍎 苹果服务", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Apple.list"),
    ("📲 电报信息", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Telegram.list"),
    ("🤖 AI服务", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AI.list"),
    ("🤖 AI服务", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list"),
    ("📹 油管视频", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list"),
    ("🎥 奈飞视频", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list"),
    ("🌍 国外媒体", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ProxyMedia.list"),
    ("🚀 节点选择", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ProxyGFWlist.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ChinaIp.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list"),
    ("🎯 全球直连", f"{RS}/ACL4SSR/ACL4SSR/master/Clash/Download.list")
]



def pem_to_b64der(pem):
    return "".join(ln.strip() for ln in pem.strip().splitlines()
                   if ln.strip() and not ln.startswith("-----"))


def entry_name(ip, port):
    """接入点名字，短一些，后面要拼进组合节点名。"""
    if ":" in ip:
        seg = ip.split(":")[2]
        tail = ip.rsplit(":", 1)[-1]
        return f"v6-{seg}-{tail}-{port}"
    return f"{'.'.join(ip.split('.')[2:])}-{port}"


def masque_node(name, ip, port, priv, pub, v4, v6, sni=None):
    # 裸 IPv6 含冒号，YAML 里必须加引号否则被当成映射
    srv = f'"{ip}"' if ":" in ip else ip
    extra = f"\n    sni: {sni}" if sni else ""
    return f"""  - name: {name}
    type: masque
    server: {srv}
    port: {port}{extra}
    private-key: {priv}
    public-key: {pub}
    ip: {v4}
    ipv6: {v6}
    mtu: 1280
    udp: true
    remote-dns-resolve: true
    dns: [1.1.1.1, 2606:4700:4700::1111]"""


def opera_landings(binary):
    """跑 opera-proxy 拿匿名凭据和落地服务器清单。"""
    out = []
    for code, loc in REGIONS.items():
        r = subprocess.run([binary, "-country", code, "-list-proxies"],
                           capture_output=True, text=True, timeout=180)
        login = re.search(r"Proxy login: (\S+)", r.stdout)
        pw = re.search(r"Proxy password: (\S+)", r.stdout)
        if not (login and pw):
            print(f"警告: {code} 区取凭据失败，跳过", file=sys.stderr)
            continue
        seq = 0
        for line in r.stdout.splitlines():
            m = re.match(r"^([\w.-]+\.sec-tunnel\.com),([\d.]+),(\d+)$",
                         line.strip())
            if not m:
                continue
            host, ip, port = m.groups()
            seq += 1
            out.append({"loc": loc, "tag": f"{loc}{seq}", "host": host,
                        "ip": ip, "port": int(port),
                        "user": login.group(1), "pw": pw.group(1)})
    return out


def build(cfg, landings):
    priv = cfg["private_key"].strip()
    if priv.startswith("-----"):
        priv = pem_to_b64der(priv)
    pub = pem_to_b64der(cfg["endpoint_pub_key"])
    v4, v6 = cfg["ipv4"], cfg["ipv6"]

    # 1. 全部 MASQUE 接入点
    entries, proxies = [], []
    for ip in V4 + V6:
        for port in PORTS:
            n = entry_name(ip, port)
            entries.append(n)
            proxies.append(masque_node(n, ip, port, priv, pub, v4, v6))
    entries.append("官方域名")
    proxies.append(masque_node("官方域名", SNI_NODE[0], SNI_NODE[1],
                               priv, pub, v4, v6, OFFICIAL_SNI))

    # 2. 落地 × 接入点 全组合
    by_loc = {}
    for land in landings:
        for ent in entries:
            name = f"{land['tag']}@{ent}"
            by_loc.setdefault(land["loc"], []).append(name)
            proxies.append(
                f'  - {{name: "{name}", type: http, server: {land["ip"]}, '
                f'port: {land["port"]}, username: {land["user"]}, '
                f'password: {land["pw"]}, tls: true, sni: {land["host"]}, '
                f'skip-cert-verify: false, dialer-proxy: {ent}}}')

    combos = sum(len(v) for v in by_loc.values())

    def q(items, n=6):
        return "\n".join(" " * n + f'- "{x}"' for x in items)

    def plain(items, n=6):
        return "\n".join(" " * n + f"- {x}" for x in items)

    # 组合数太多，平铺在一个组里没法选，按地区收成 url-test
    loc_names = [f"{loc}线路" for loc in by_loc]
    loc_defs = "\n\n".join(f"""  - name: {loc}线路
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 80
    lazy: true
    proxies:
{q(tags)}""" for loc, tags in by_loc.items())

    prov, rules = [], []
    for i, (group, url) in enumerate(RULESETS):
        pn = f"rule{i:02d}"
        prov.append(f"""  {pn}:
    type: http
    behavior: classical
    format: text
    interval: 86400
    url: {url}
    path: ./ruleset/{pn}.list""")
        rules.append(f"  - RULE-SET,{pn},{group}")

    yaml = f"""
    
port: 7890
socks-port: 7891
allow-lan: true
bind-address: "*"
ipv6: false
mode: Rule
log-level: info
external-controller: 127.0.0.1:9090

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - '+.push.apple.com'
    - '+.apple.com'

dns:
  enable: true
  ipv6: false
  listen: 0.0.0.0:53
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  fake-ip-filter:
    - "*.lan"
    - "*.local"
    - "*.arpa"
    - time.*.com
    - ntp.*.com
    - +.market.xiaomi.com
    - localhost.ptlogin2.qq.com
    - "*.msftncsi.com"
    - www.msftconnecttest.com
  default-nameserver:
    - 119.29.29.29
    - 223.5.5.5
  nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  nameserver-policy:
    geosite:cn:
      - https://doh.pub/dns-query
      - https://dns.alidns.com/dns-query
    geosite:geolocation-!cn:
      - https://dns.cloudflare.com/dns-query
      - https://dns.google/dns-query
  proxy-server-nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - https://dns.cloudflare.com/dns-query
    - https://dns.google/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN
    geosite:
      - gfw
    ipcidr:
      - 240.0.0.0/4

proxies:
{chr(10).join(proxies)}

proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
{plain(loc_names)}
      - 🔄 故障转移

  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    lazy: true
    proxies:
{plain(loc_names)}

  - name: 🔄 故障转移
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 180
    lazy: true
    proxies:
{plain(loc_names)}

{loc_defs}

  - name: 📹 油管视频
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
{plain(loc_names)}

  - name: 🎥 奈飞视频
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
{plain(loc_names)}

  - name: 🌍 国外媒体
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - 🎯 全球直连

  - name: 📲 电报信息
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🎯 全球直连

  - name: 🤖 AI服务
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
{plain(loc_names)}

  - name: Ⓜ️ 微软服务
    type: select
    proxies:
      - 🎯 全球直连
      - 🚀 节点选择
      - ♻️ 自动选择

  - name: 🍎 苹果服务
    type: select
    proxies:
      - 🎯 全球直连
      - 🚀 节点选择
      - ♻️ 自动选择

  - name: 📢 谷歌FCM
    type: select
    proxies:
      - 🚀 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择

  - name: 🎯 全球直连
    type: select
    proxies:
      - DIRECT
      - 🚀 节点选择
      - ♻️ 自动选择

  - name: 🛑 全球拦截
    type: select
    proxies:
      - REJECT
      - DIRECT

  - name: 🍃 应用净化
    type: select
    proxies:
      - REJECT
      - DIRECT

  - name: 🐟 漏网之鱼
    type: select
    proxies:
      - 🚀 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择

rule-providers:
{chr(10).join(prov)}

rules:
{chr(10).join(rules)}
  - GEOIP,LAN,🎯 全球直连,no-resolve
  - GEOIP,CN,🎯 全球直连
  - MATCH,🐟 漏网之鱼
"""
    return yaml, len(entries), len(landings), combos


def main():
    if len(sys.argv) < 4:
        print("用法: gen.py <usque-config.json> <opera-proxy> <输出目录>",
              file=sys.stderr)
        sys.exit(1)
    cfg_path, opera_bin, outdir = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(cfg_path) as f:
        cfg = json.load(f)

    landings = opera_landings(opera_bin)
    if not landings:
        sys.exit("一个 Opera 落地都没取到，可能是源 IP 被限速，换台机器再试")

    yaml, n_entry, n_land, n_combo = build(cfg, landings)

    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "opera-masque.yaml")
    with open(path, "w") as f:
        f.write(yaml)

    print(f"已生成 {path}")
    print(f"MASQUE 接入点 {n_entry} 个")
    print(f"Opera 落地   {n_land} 个: "
          + ", ".join(sorted({l['tag'] for l in landings})))
    print(f"组合节点     {n_combo} 个")


if __name__ == "__main__":
    main()
