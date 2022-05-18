from database import MyLogger
from mac_vendor_lookup import MacLookup
import subprocess
import re


class ArpScan():
    def __init__(self) -> None:
        print("init Arpscan...")
        self.mylogger = MyLogger.MyLogger()
    
    def execute_arpscan(self, node, link, node_id):
        print("execute arpscan...")
        self.mylogger.writelog("execute arpscan...","info")

        try:
            res = subprocess.check_output('arp-scan -l -x -N -r 1 -g', shell=True).decode('UTF-8')
            print(res)
            self.mylogger.writelog("arpscan result = \n" + res, "info")
        except:
            print("arpscan error!")
            self.mylogger.writelog("arpscan error", "error")
        
        # 除去 .1 .2 .254 
        tmp = re.split('\n', res)
        res = ""
        for i in range(2,len(tmp)-2) :
            print(i)
            res += tmp[i] +'\n'
        print(res)

        iplist = re.split('\t|\n', res)
        iplist.pop(-1)
        print(iplist)

        if len(iplist) == 0:
            print("No devices in this LAN")
            self.mylogger.writelog("No devices in this LAN", "info")
            exit(0)
        
        keys = ['id', 'mac', 'vendor']

        if (node_id == 0):
            d = {}
            d['id'] = self.get_ipaddr()
            d['mac'] = self.get_macaddr()
            d['vendor'] = "Ubuntu20.04"
            d['group'] = node_id
            d['ports'] = []
            d['os'] = "Ubuntu20.04"
            d['node_id'] = 0
            d['session'] = ""
            d['ics_protocol'] = {}
            d['ics_device'] = 0
            d['secret_data'] = 0
            d['goap'] = {
                'Symbol_ProcessMigrate':None,
                'Symbol_ArpPoisoning':None,
                'Symbol_ValidUser':None,
                'Symbol_DCCheck':None,
                'Symbol_GetLanNodes':True,
                'Symbol_SearchMainDrive':None,
                'Symbol_CreateUser':None,
                'Symbol_SearchNwDrive':None,
                'Symbol_LateralMovement':None,
                'Symbol_DomainUser':None,
                'Symbol_MainDriveInfo':None,
                'Symbol_LogonUserInfo':None,
                'Symbol_TcpScan':None,
                'Symbol_UdpScan':None,
                'Symbol_GetNetworkInfo':None,
                'Symbol_NwDriveInfo':None,
                'Symbol_IdentOs':None,
                'Symbol_GetOsPatch':None,
                'GoalSymbol_GetLocalSecretInfo':None,
                'Symbol_ProcessInfo':None,
                'GoalSymbol_GetNwSecretInfo':None,
                'Symbol_PrivilegeEscalation':None,
                'Symbol_LocalUser':None
            }
            d['local_account_list'] = []        # 本地账户列表
            d['local_account_pass'] = []        # 本地账户密码
            d['local_account_hash'] = []        # 本地账户哈希
            d['domain_account_list'] = []       # 域账户列表
            d['domain_account_pass'] = []       # 域账户密码
            d['domain_account_hash'] = []       # 域账户哈希
            d['dc'] = []
            d['domain_info'] = []               # 域信息
            d['process_list'] = []              # 进程信息
            d['security_process'] = []          # 安全信息
            d['ipconfig_info'] = []
            d['netstat_info'] = []
            d['network_drive'] = []
            d['local_drive'] = []
            d['pcap_list'] = []
            d['os_patches'] = []
            d['local_vuln_list'] = []
            node.append(d)
        

        for num in range(0, len(iplist), 3):
            d = dict(zip(keys, iplist[num:num+3]))
            d['group'] = node_id
            d['os'] = 'unknown'
            d['node_id'] = num//3 + 1 + node_id
            d['session'] = ""
            d['ics_protocol'] = {}
            d['ics_device'] = 0
            d['secret_data'] = 0
            d['goap'] = {
                'Symbol_ProcessMigrate':None,
                'Symbol_ArpPoisoning':None,
                'Symbol_ValidUser':None,
                'Symbol_DCCheck':None,
                'Symbol_GetLanNodes':True,
                'Symbol_SearchMainDrive':None,
                'Symbol_CreateUser':None,
                'Symbol_SearchNwDrive':None,
                'Symbol_LateralMovement':None,
                'Symbol_DomainUser':None,
                'Symbol_MainDriveInfo':None,
                'Symbol_LogonUserInfo':None,
                'Symbol_TcpScan':None,
                'Symbol_UdpScan':None,
                'Symbol_GetNetworkInfo':None,
                'Symbol_NwDriveInfo':None,
                'Symbol_IdentOs':None,
                'Symbol_GetOsPatch':None,
                'GoalSymbol_GetLocalSecretInfo':None,
                'Symbol_ProcessInfo':None,
                'GoalSymbol_GetNwSecretInfo':None,
                'Symbol_PrivilegeEscalation':None,
                'Symbol_LocalUser':None
            }
            d['local_account_list'] = []
            d['local_account_pass'] = []
            d['local_account_hash'] = []
            d['domain_account_list'] = []
            d['domain_account_pass'] = []
            d['domain_account_hash'] = []
            d['dc'] = []
            d['domain_info'] = []
            d['process_list'] = []
            d['security_process'] = []
            d['ipconfig_info'] = []
            d['netstat_info'] = []
            d['network_drive'] = []
            d['local_drive'] = []
            d['pcap_list'] = []
            d['os_patches'] = []
            d['local_vuln_list'] = []
            #node["node"+str(node_num)] = d
            node.append(d)

        keys = ['target']

        for num in range(0, len(iplist), 3):
            d = dict(zip(keys, iplist[num:num+1]))
            d['source'] = self.get_ipaddr()
            d['node_id'] = num//3 + 1 + node_id
            d['value'] = 1
            link.append(d)
        # print(link)

        node_id = num//3 + 1 + node_id
        return node_id

    def get_ipaddr(self):
        try:
            res = subprocess.check_output('ifconfig | grep -A3 ens33 | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'', shell=True).decode('utf-8')
            #print(res)
            return res.replace('\n', '')
        except:
            print("get-ipaddr error!!")
            self.mlogger.writelog("get-ipaddr error!!", "error")


    def get_macaddr(self):
        try:
            res = subprocess.check_output('ifconfig | grep -A3 ens33 | grep -oP \'ether ..:..:..:..:..:..\' | sed \'s/ether //\'', shell=True).decode('utf-8')
            #print(res)
            return res.replace('\n', '')
        except:
            print("get-macaddr error!!")
            self.mlogger.writelog("get-macaddr error!!", "error")
