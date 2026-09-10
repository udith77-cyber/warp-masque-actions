#!/usr/bin/env python3
"""
注册 Cloudflare WARP (MASQUE) 设备并生成 mihomo 配置。

需要先跑 usque register 拿到 config.json，本脚本负责把它转成
带全部可用 endpoint 的 mihomo yaml。

用法:
    python3 gen_masque.py <usque-config.json> <输出目录>
"""
import json
import os
import sys
import urllib.parse

# 全部经真机握手实测（2026-09-05，psg2）
# QUIC 回包不等于能建隧道：162.159.194/196/197/204 段与 v6 的 102/105 段
# 会回包但 login 失败，已剔除。
V4 = ["162.159.198.1", "162.159.198.2", "162.159.199.1", "162.159.199.2"]
V6 = ["2606:4700:103::1", "2606:4700:103::2",
      "2606:4700:104::1", "2606:4700:104::2"]
# 4443/8095 是后来补测出来的，实测 8/8 全通
PORTS = (443, 500, 1701, 4500, 4443, 8443, 8095)

# CF 没有 A 记录指向 MASQUE 段，官方域名只能用在 SNI 上
OFFICIAL_SNI = "zt-masque.cloudflareclient.com"
SNI_NODE = ("162.159.198.1", 443)

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
    return "".join(
        ln.strip() for ln in pem.strip().splitlines()
        if ln.strip() and not ln.startswith("-----")
    )


def node(name, ip, port, priv, pub, v4, v6, sni=None):
    # 裸 IPv6 含冒号，YAML 里必须加引号否则被解析成映射
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


def node_name(ip, port):
    if ":" in ip:
        seg = ip.split(":")[2]
        tail = ip.rsplit(":", 1)[-1]
        return f"WARP6-{seg}-{tail}-{port}"
    return f"WARP-{'.'.join(ip.split('.')[2:])}-{port}"


def masque_links(cfg, priv, pub):
    """生成 Shadowrocket 用的 masque:// 链接。

    格式参数与字段名对齐 Shadowrocket 的 masque 实现：
    masque://<endpoint_ip>:<port>?publicKey=&privateKey=&ip=&dns=&udp=&cc=&flag=#<名称>
    publicKey 用剥掉 PEM 头尾的 base64 DER，privateKey 直接用 usque 的原值。
    逗号不转义（Shadowrocket 的 dns 字段接受逗号分隔）。
    """
    def enc(v):
        return urllib.parse.quote(str(v), safe="").replace("%2C", ",")

    lines = []
    for ip in V4 + V6:
        for port in PORTS:
            params = "&".join([
                "publicKey=" + enc(pub),
                "privateKey=" + enc(priv),
                "ip=" + enc(cfg["ipv4"]),
                "dns=" + enc("1.1.1.1, 8.8.8.8"),
                "udp=1",
                "cc=" + enc(""),
                "flag=" + enc("CDN"),
            ])
            host = "[%s]" % ip if ":" in ip else ip
            name = node_name(ip, port)
            lines.append("masque://%s:%d?%s#%s" % (host, port, params, enc(name)))
    return lines


def build(cfg):
    priv = cfg["private_key"].strip()
    if priv.startswith("-----"):
        priv = pem_to_b64der(priv)
    pub = pem_to_b64der(cfg["endpoint_pub_key"])
    v4, v6 = cfg["ipv4"], cfg["ipv6"]

    names, proxies = [], []
    for ip in V4 + V6:
        for port in PORTS:
            name = node_name(ip, port)
            names.append(name)
            proxies.append(node(name, ip, port, priv, pub, v4, v6))

    names.append("WARP-官方域名")
    proxies.append(node("WARP-官方域名", SNI_NODE[0], SNI_NODE[1],
                        priv, pub, v4, v6, OFFICIAL_SNI))

    ind = lambda lst, n=6: "\n".join(" " * n + f"- {x}" for x in lst)

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

    links = masque_links(cfg, priv, pub)

    return links, f"""
  
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
      - 🔄 故障转移
      - ☑️ 手动切换
      - DIRECT

  - name: ☑️ 手动切换
    type: select
    proxies:
{ind(names)}

  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    lazy: false
    proxies:
{ind(names)}

  - name: 🔄 故障转移
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 180
    proxies:
{ind(names)}

  - name: 📹 油管视频
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换
      - DIRECT

  - name: 🎥 奈飞视频
    type: select
    proxies:
      - 🚀 节点选择
      - ♻️ 自动选择
      - 🔄 故障转移
      - ☑️ 手动切换
      - DIRECT

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
      - ☑️ 手动切换
      - DIRECT

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
""", len(names)


def main():
    if len(sys.argv) < 3:
        print("用法: gen_masque.py <usque-config.json> <输出目录>", file=sys.stderr)
        sys.exit(1)
    src, outdir = sys.argv[1], sys.argv[2]
    with open(src) as f:
        cfg = json.load(f)

    os.makedirs(outdir, exist_ok=True)
    links, yaml, count = build(cfg)

    path = os.path.join(outdir, "warp-masque.yaml")
    with open(path, "w") as f:
        f.write(yaml)

    txt = os.path.join(outdir, "warp-masque-shadowrocket.txt")
    with open(txt, "w") as f:
        f.write("\n".join(links) + "\n")

    print(f"已生成 {path}")
    print(f"已生成 {txt}（{len(links)} 条 masque:// 链接）")
    print(f"节点数 {count}")
    print(f"内网地址 {cfg['ipv4']} / {cfg['ipv6']}")


if __name__ == "__main__":
    main()
