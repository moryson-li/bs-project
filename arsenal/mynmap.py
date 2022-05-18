from lib2to3.pytree import type_repr
from tempfile import TemporaryFile
from chardet import detect
from database import MyLogger
import subprocess
import re
import copy
import pprint

class MyNmap:
    def __init__(self) -> None:
        print("init MyNmap...")
        self.mylogger = MyLogger.MyLogger()

    def execute_nmap(self, ip_addr, num, node, proxy):
        # 对ip_addr进行nmap，查看开放端口，并将这些信息写进goap_node中
        detect_ports = []
        d = {}
        flag = 0
        windows_count = 0
        linux_count = 0

        print("\nexecute nmap to {}...".format(ip_addr))
        self.mylogger.writelog("execute nmap to " + ip_addr, "info")

        check_port = '1-1000'

        try:
            if proxy == 0:
                # 直接nmap
                res = subprocess.check_output('nmap -sSV -O -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
            else:
                # 使用代理nmap
                res = subprocess.check_output('proxychains4 nmap -sTV -O -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
            rows = re.split('\n',res)
            
            for row in rows:
                if '/tcp' not in row:
                    flag = 0
                if flag == 1:
                    row = row.replace('\n', '')
                    row = re.sub(r'\s+', ' ', row)
                    c = row.split(' ', 3)
                    d["number"] = c[0]
                    d["service"] = c[2]
                    try:
                        if c[3]:
                            d["version"] = c[3]
                    except:
                        d["version"] = ""
                    detect_ports.append(copy.deepcopy(d))
                if 'SERVICE' and 'VERSION' in row:
                    flag = 1
                if 'windows' in row.lower():
                    windows_count = windows_count + 1
                if 'linux' in row.lower():
                    linux_count = linux_count + 1

        except:
            print("NO TCP port open!!!")
            self.mylogger.writelog("NO TPC port open!!!", "error")
        
        print("detect_ports = {}".format(detect_ports))
        print("windows_count = {}".format(windows_count))
        print("linux_count = {}".format(linux_count))

        self.mylogger.writelog("detect_ports =  " + pprint.pformat(detect_ports), "info")

        if(windows_count == 0 and linux_count == 0):
            node[num]["os"] = "Unknown"
        elif (windows_count > 0 and windows_count >= linux_count):
            node[num]["os"] = "Windows"
        elif (windows_count < linux_count):
            node[num]["os"] = "Linux"
        
        node[num]["goap"]["Symbol_TcpScan"] = True
        node[num]["goap"]["Symbol_IdentOs"] = True

        detect_ports.clear()

        
        
