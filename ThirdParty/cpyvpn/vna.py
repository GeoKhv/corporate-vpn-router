# coding: utf-8
# Created on 30.11.2020
# Copyright © 2020-2021 Nick Krylov.
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import shlex
import socket
import signal
import subprocess
import fcntl
import ctypes
import logging

from . import utils

logger = logging.getLogger()

# Linux specific block
IFNAMSIZ = 16
sin_addr_t = ctypes.c_byte * 4


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),  # sin_family
                ("sin_port", ctypes.c_ushort),
                ("sin_addr", sin_addr_t),
                ("__pad", ctypes.c_byte * 8)]  # struct sockaddr_in is 16 bytes


class ifmap(ctypes.Structure):
    _fields_ = [
    ("mem_start", ctypes.c_ulong),
    ("mem_end", ctypes.c_ulong),
    ("base_addr", ctypes.c_short),
    ("irq", ctypes.c_byte),
    ("dma", ctypes.c_byte),
    ("port", ctypes.c_byte)
    ]


class ifr_ifrn(ctypes.Structure):
    _fields_ = [("ifrn_name", ctypes.c_char * IFNAMSIZ)]


class ifr_ifru(ctypes.Union):
    _fields_ = [
        ("ifru_addr", sockaddr),
        ("ifru_dstaddr", sockaddr),
        ("ifru_broadaddr", sockaddr),
        ("ifru_netmask", sockaddr),
        ("ifru_hwaddr", sockaddr),

        ("ifru_flags", ctypes.c_short),
        ("ifru_ivalue", ctypes.c_int),
        ("ifru_mtu", ctypes.c_int),

        ("ifru_map", ifmap),
#         char ifru_slave[IFNAMSIZ];      /* Just fits the size */
        ("ifru_slave", ctypes.c_char * IFNAMSIZ),
        ("ifru_newname", ctypes.c_char * IFNAMSIZ),
        ("ifru_data", ctypes.c_void_p),
         ]


class ifreq(ctypes.Structure):
    _fields_ = [
        ("ifr_ifrn", ifr_ifrn),
        ("ifr_ifru", ifr_ifru),
        ]


class SocketWrapper:

    def __init__(self, sock):
        self.sock = sock

    def read(self, sz):
        return self.sock.recv(sz)

    def write(self, data):
        return self.sock.send(data)

    def fileno(self):
        return self.sock.fileno()

    def close(self):
        self.sock.close()


class TunTapDevice:
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    IFF_UP = 1 << 0

    TUNSETIFF = 0x400454ca # =_IOW('T', 202, "int")
    UTUN_CONTROL_NAME = "com.apple.net.utun_control"
    bINET = int(socket.AF_INET).to_bytes(4, "big")
    bINET6 = int(socket.AF_INET6).to_bytes(4, "big")

    def _open_utun(self):
        s = socket.socket(socket.PF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL)
        s.connect(self.UTUN_CONTROL_NAME)
        unit_id = s.getpeername()[1]
        self.name = "utun{}".format(unit_id - 1)
        self.f = SocketWrapper(s)
        self.fd = self.f.fileno()
        self.af_hdr = True

    def _open_tun(self, name, dev, tun, nopi):
        self.fd = fd = os.open(dev, os.O_RDWR)
        self.f = open(fd, 'rb+', buffering=0)

        try:
            name = name.encode("latin1")
        except AttributeError:
            pass

        req = ifreq()
        flags = self.IFF_TUN if tun else self.IFF_TAP
        if nopi:
            flags |= self.IFF_NO_PI
        req.ifr_ifrn.ifrn_name = name
        req.ifr_ifru.ifru_flags = flags
        reqba = bytearray(req)
        if fcntl.ioctl(fd, self.TUNSETIFF, reqba):
            raise RuntimeError("ioctl failed!")

        reqret = ifreq.from_buffer(reqba)
        self.name = reqret.ifr_ifrn.ifrn_name
        if name and name != self.name:
            raise RuntimeError("Bad iface name!")

    def __init__(self, name="", dev="/dev/net/tun", tun=True, nopi=True, mtu=1500):
        self.af_hdr = False
        if utils.is_mac:
            self._open_utun()
        else:
            self._open_tun(name, dev, tun, nopi)
        self.mtu = mtu

    def read(self):
        d = self.f.read(self.mtu)
        if self.af_hdr:
            d = d[4:]
        return d

    def write(self, data):
        if self.af_hdr:
            afh = 0
            # Check high 4 bits:
            ptype = data[0] >> 4
            if ptype == 4:
                afh = self.bINET
            elif ptype == 6:
                afh = self.bINET6
            else:
                return
            data = afh + data
        return self.f.write(data)

    def fileno(self):
        return self.fd

    def close(self):
        self.f.close()

class VNAUnavailable(Exception):
    pass

class VNABase(object):

    def __init__(self, up_on_init=False):
        self.addr = None
        self.is_up = up_on_init
        self.netmask = None

    def set_ips(self, addr, gw, nm=None):
        self.addr = addr
        self.gw = gw
        self.netmask = nm

    def om_ip(self):
        return self.addr

    def set_dns(self, ips, domains):
        MAXNS = len(ips)
        ns = 0
        has_systemd_resolved = False
        try:
            socket.gethostbyname("_gateway")#systemd-resolved synthetic record
            has_systemd_resolved = True
        except:
            pass
        if utils.is_linux and not has_systemd_resolved:
            try:
                with open("/etc/resolv.conf", "rt") as resolv:
                    for l in resolv:
                        if "nameserver" in l:
                            ns += 1
                MAXNS = 3
            except:
                pass
        ips = ips[:max(1, MAXNS - ns)]
        self._set_dns(ips, domains)

    def tun_up(self):
        return self.is_up

    def tundev(self):
        return self.dev

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.down()

    @classmethod
    def ctz(cls,x):
        return ((x&-x).bit_length() -1)

    @classmethod
    def clz(cls, x):
        # Keep shifting 32-bit x by one until
        # leftmost bit does not become 1.
        mask = 1 << 31
        res = 0
        while ((x & mask) == 0):
            x = (x << 1)
            res += 1
        return res

    @classmethod
    def gen_ranges(cls, ip_min, ip_max):
        mask32 = 0xffffffff
        ret = []

        def calc_mask(n_mask_bits):
            return (1 << n_mask_bits) - 1

        def add_sub(start, mask):
            ret.append((utils.ipint2str(start), 32 - mask.bit_length(), utils.ipint2str((~mask) & mask32)))

        # Split a range of IP addresses into subnets
        # https://gist.github.com/vmxdev/2592304836c542c1e6022e2589fc0f64
        start, end = ip_min, ip_max
        sub_start = start
        while 1:
            if sub_start > end:
                break
            elif sub_start == end:
                add_sub(sub_start, 0)
                break

            n_mask_bits = cls.ctz(sub_start)
            mask = calc_mask(n_mask_bits)
            sub_end = sub_start + mask

            if sub_end == end:
                add_sub(sub_start, mask)
                break
            elif sub_end > end:
                diff = end - sub_start + 1
                p = 32 - cls.clz(diff) - 1
                ndiff = 1 << p
                add_sub(sub_start, calc_mask(p))
                sub_start += ndiff
            else:
                add_sub(sub_start, mask)
                sub_start = sub_end + 1
        return ret


__def_snx_name__ = "snxtun"

STDOUT = subprocess.STDOUT
PIPE = subprocess.PIPE
DEVNULL = subprocess.DEVNULL

# Use  Network Manager to setup tun in user mode (without root)
# https://mail.gnome.org/archives/networkmanager-list/2016-January/msg00053.html

class VNANM(VNABase):

    @staticmethod
    def run_nmcli(cmd, opt=[]):
        cmd = ["nmcli", "-c", "no", "-t"] + opt + ["c"] + cmd
        try:
            ret = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, check=True)
        except subprocess.CalledProcessError as e:
            raise RuntimeError("nmcli failed with retcode={}. Error message: {}".format(e.returncode, e.stderr)) from None
        return ret.stdout

    def __init__(self, args):
        super(VNANM, self).__init__()
        try:
            self.run_nmcli([])
        except:
            raise VNAUnavailable()
        self.name = name = args.get("interface", __def_snx_name__)
        self.tun = tun = args.get("tun", True)
        self.nopi = nopi = args.get("nopi", True)
        self.mtu = mtu = args.get("mtu", 1500)

        uid = os.getuid()
        newtun = True
        ntun = 0
        for l in self.run_nmcli(["s"]).split("\n"):
            if l.partition(":")[0] == name:
                ntun += 1
        if ntun == 1:
            ret = self.run_nmcli(["s" , self.name ])
            for l in ret.split("\n"):
                if "owner" in l:
                    tunuid = int(l.partition(":")[2])
                    if uid == tunuid:
                        newtun = False
                        break
        if newtun:
            if ntun != 0:
                self.run_nmcli(["del" , self.name ])
            self.run_nmcli(["add", "type", "tun", "ifname", name, "con-name", name , "mode", "tun" if tun else "tap", "tun.pi", "no" if nopi else "yes",
                       "owner", str(uid), "autoconnect", "no", "ip4", "192.0.0.8"])
        self.set_mtu(mtu)

        self.run_nmcli(["up" , self.name ])
        self._init_dev()
        self.down()

    def _init_dev(self):
        self.dev = TunTapDevice(self.name, tun=self.tun, nopi=self.nopi, mtu=self.mtu)

    def set_mtu(self, mtu):
        self.run_nmcli([ "mod" , self.name, "ethernet.mtu", str(mtu)])

    def _set_dns(self, ips, domains):
        allips = " ".join(ips)
        if ips:
            self.run_nmcli([ "mod" , self.name, "ipv4.dns", allips])
            self.run_nmcli([ "mod" , self.name, "ipv4.dns-priority", "50"])  # NM default for VPN
        if domains:
            self.run_nmcli([ "mod" , self.name, "ipv4.dns-search", " ".join(domains)])

    def set_routes(self, routes):

        self.routes = routes
        lst = []
        for itm in routes:
            for ip, masklen, _ in self.gen_ranges(utils.ipstr2int(itm[0]), utils.ipstr2int(itm[1])):
                addr = "{}/{}".format(ip, masklen)
                lst.append(addr)
        all_routes = ",".join(lst)
        self.run_nmcli(["mod" , self.name, "ipv4.routes", all_routes])

    def down(self):
        if self.run_nmcli(["show" , self.name], ["-f", "GENERAL.STATE"]):
            self.run_nmcli(["down" , self.name])
            self.dev.close()
        self.is_up = False

    def up(self):
        self.down()
        addr = self.om_ip()
        if self.netmask:
            msklen = 32 - self.ctz(utils.ipstr2int(self.netmask))
            addr += "/{}".format(msklen)
        self.run_nmcli(["mod" , self.name, "ipv4.addresses", addr])

        self.run_nmcli(["up" , self.name ])
        self._init_dev()
        self.is_up = True


class VNAVPNC(VNABase):

    def __init__(self, args):
        self._vpnc = args.get("script")
        if not self._vpnc:
            raise VNAUnavailable()
        super(VNAVPNC, self).__init__()
        self._uid = args.get("uid")  # !
        defname = args.get("interface", __def_snx_name__)
        self._env = {"VPNPID":str(os.getpid()), "TUNDEV":defname, "INTERNAL_IP4_MTU":"1500"}

        self.run_vpnc("pre-init")

        self.dev = TunTapDevice(defname)
        self._env["TUNDEV"] = self.dev.name

    def run_vpnc(self, reason):
        env = dict(self._env)
        env.update({"reason":reason})
        kw = {"env":env, "stdin":DEVNULL, "stdout":DEVNULL, "stderr":STDOUT, "check":True}
        kw["INTERNAL_IP4_ADDRESS"] = self.om_ip()
        if self.netmask:
            kw["INTERNAL_IP4_NETMASK"] = self.netmask
        kw["VPNGATEWAY"] = self.gw
        subprocess.run([self._vpnc], **kw)

    def set_mtu(self, mtu):
        self._env["INTERNAL_IP4_MTU"] = str(mtu)

    def _set_dns(self, ips, domains):
        self._env["INTERNAL_IP4_DNS"] = " ".join(ips)
        if domains:
            self._env["CISCO_DEF_DOMAIN"] = " ".join(domains)

    def set_routes(self, routes):
        idx = 0
        for itm in routes:

            ranges = self.gen_ranges(utils.ipstr2int(itm[0]), utils.ipstr2int(itm[1]))

            for ip, masklen, mask in ranges:
                pref = "CISCO_SPLIT_INC_{}_".format(idx)
                self._env[pref + "ADDR"] = ip
                self._env[pref + "MASK"] = mask
                self._env[pref + "MASKLEN"] = str(masklen)
                idx += 1

        self._env["CISCO_SPLIT_INC"] = str(idx)

    def down(self):
        if self.is_up:
            self.run_vpnc("disconnect")
            self.dev.close()
            self.dev = None
            self.is_up = False

    def up(self):
        self.down()
        self.run_vpnc("connect")
        if self.dev is None:
            self.dev = TunTapDevice(self._env["TUNDEV"])
            self._env["TUNDEV"] = self.dev.name
        self.is_up = True


class NullDev():

    def __init__(self):
        self.fd = 0

    def read(self):
        return b""

    def write(self, data):
        pass

    def fileno(self):
        return self.fd

    def close(self):
        os.close(self.fd)


class VNANull(VNABase):

    def __init__(self, args):
        super(VNANull, self).__init__(True)
        self.dev = NullDev()

    def _ignore(self, *args):
        pass

    set_ips = set_routes = set_dns = up = down = _ignore


class SocketPairDev(SocketWrapper):

    def __init__(self):
        self.sp = socket.socketpair(None, socket.SOCK_DGRAM)
        self.proxy_sock().set_inheritable(True)
        self.max_len = 65536  # IPv4 max
        super().__init__(self.sp[0])

    def proxy_sock(self):
        return self.sp[1]

    def read(self):
        rcv = super().read(self.max_len)
        return rcv if rcv else None

class VNAProxy(VNABase):

    def __init__(self, args):
        super(VNAProxy, self).__init__()
        self._script = args.get("script_tun")
        if not self._script:
            raise VNAUnavailable()

        self.dev = SocketPairDev()
        self._dns = ""
        self._sc_proc = None
        self.mtu = args.get("mtu", 1500)

    def set_mtu(self, mtu):
        self.mtu = mtu

    def set_routes(self, _):
        pass

    def _set_dns(self, ips, domains):
        self._dns = " ".join(ips)
        self._domain = domains[0] if domains else ""

    def up(self):
        self._sc_proc = None
        proxy_sock = self.dev.proxy_sock()
        vpnfd = proxy_sock.fileno()
        env = {
            "VPNFD":str(vpnfd),
            "INTERNAL_IP4_ADDRESS": self.om_ip(),
            "INTERNAL_IP4_MTU":str(self.mtu)
            }
        if self._dns:
            env["INTERNAL_IP4_DNS"] = self._dns
            if self._domain:
                env["CISCO_DEF_DOMAIN"] = self._domain  # only one domain supported

        DEVNULL = subprocess.DEVNULL
        kw = {"env":env, "start_new_session":True, "pass_fds":(vpnfd,),
            "stdin":DEVNULL, "stdout":DEVNULL, "stderr":subprocess.STDOUT
        }
        try:
            self._sc_proc = subprocess.Popen(shlex.split(self._script), **kw)
        except Exception as e:
            logger.error("Failed to run TUN script: '{}'. Error was: '{}'".format(self._script, e))
            raise e
        proxy_sock.close()
        self.is_up = True

    def down(self):
        if self._sc_proc:
            os.killpg(self._sc_proc.pid, signal.SIGHUP)
        self.dev.close()


def init_vna(args):
    cls_list = [VNAProxy, VNAVPNC, VNANM]

    if args.get("null_vna"):
        cls_list = [VNANull]
    inst = None
    for cls in cls_list:
        try:
            inst = cls(args)
            break
        except VNAUnavailable:
            pass
    if isinstance(inst, VNANull):
        logger.warning("Initializing null VNA for debugging. Network packet transfer won't be available.")
    if inst is None:
        raise RuntimeError("VNA initialisation failed! Check your -s/-S option, make sure Network Manager can handle TUN interfaces, use --null_vna hidden option.")
    return inst
