"""FakeNet-NG configuration generator."""
from . import config


def generate_fakenet_config(kali_ip=None, excluded_ports=None, excluded_processes=None):
    """Generate a FakeNet-NG INI config with triple-layer protection for the analyst host.

    The HostBlackList is the primary shield: ALL traffic to/from Kali bypasses
    interception regardless of port. Port and process blacklists are
    defense-in-depth.

    Args:
        kali_ip: IP of the analyst Kali machine (default: KALI_IP env, else the
            local address that routes to config.FLAREVM_HOST — see _detect_kali_ip)
        excluded_ports: Defense-in-depth port list (default: WinRM, SMB, IDA MCP)
        excluded_processes: Process names that handle control traffic
    """
    if kali_ip is None:
        kali_ip = config.detect_kali_ip()
    if not kali_ip:
        raise RuntimeError(
            "Cannot determine the analyst host IP for FakeNet's HostBlackList "
            "(no route to config.FLAREVM_HOST=%s). Set KALI_IP explicitly." % config.FLAREVM_HOST)
    if excluded_ports is None:
        excluded_ports = [5985, 5986, 445, 139, 13337]
    if excluded_processes is None:
        excluded_processes = ["svchost.exe", "System", "smbd.exe", "wsmprovhost.exe"]
    blacklist_ports = ",".join(str(p) for p in excluded_ports)
    blacklist_procs = ",".join(excluded_processes)
    return """[FakeNet]
DivertTraffic: Yes

[Diverter]
# NetworkMode belongs to [Diverter] in FakeNet-NG 3.x; placing it under
# [FakeNet] makes the diverter abort with "You must configure a NetworkMode".
NetworkMode: SingleHost
# PRIMARY SHIELD: never intercept traffic to/from analyst host
HostBlackList: {kali_ip}
# Process exclusions (WinRM/SMB host processes)
ProcessBlackList: {blacklist_procs}
# Port blacklist (defense-in-depth)
DefaultTCPListener: RawTCPListener
DefaultUDPListener: RawUDPListener
BlackListPortsTCP: {blacklist_ports}
BlackListPortsUDP:

[RawTCPListener]
Enabled: True
Port: 1337
Protocol: TCP
Listener: RawListener
UseSSL: No
Timeout: 10

[RawUDPListener]
Enabled: True
Port: 1337
Protocol: UDP
Listener: RawListener
Timeout: 10

[DNSListener]
Enabled: True
Port: 53
Protocol: UDP
Listener: DNSListener
ResponseA: 192.0.2.123
ResponseAAAA: ::1
ResponseMX: mail.evil.com
ResponseTXT: FAKENET
NXDomains: 0

[HTTPListener80]
Enabled: True
Port: 80
Protocol: TCP
Listener: HTTPListener
UseSSL: No
Webroot: C:\\Tools\\fakenet\\fakenet3.5\\defaultFiles\\
DumpHTTPPosts: Yes
DumpHTTPPostsFilePrefix: http

[HTTPListener443]
Enabled: True
Port: 443
Protocol: TCP
Listener: HTTPListener
UseSSL: Yes
Webroot: C:\\Tools\\fakenet\\fakenet3.5\\defaultFiles\\
DumpHTTPPosts: Yes
DumpHTTPPostsFilePrefix: https

[SMTPListener]
Enabled: True
Port: 25
Protocol: TCP
Listener: SMTPListener

[FTPListener]
Enabled: True
Port: 21
Protocol: TCP
Listener: FTPListener
UseSSL: No

[IRCListener]
Enabled: True
Port: 6667
Protocol: TCP
Listener: IRCListener
""".format(
        kali_ip=kali_ip,
        blacklist_procs=blacklist_procs,
        blacklist_ports=blacklist_ports,
    )
