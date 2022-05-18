from arsenal import arpscan
from arsenal import mynmap
from arsenal import msploit
from database import write_json
from database import attack_tree
from database import MyLogger
from ipaddress import IPv4Address
import copy
import json
import pprint
import random
import subprocess


class GoapSymbol():
    node = []  # 网络节点
    link = []
    node_json = {}
    node_id = 0
    pre_node_id = 0
    local_ipaddr = ""
    class_a = []
    class_b = []

    def __init__(self, actionfile):
        print("init GoapSymbol")

        self.actions = self.load_action(actionfile)  # 加载action文件

        self.local_ipaddr = self.get_ipaddr()

        self.pre_exe = None

        # 定义A类地址
        self.class_a.append('10.0.0.0')
        for num in range(1, 256):
            self.class_a.append(str(IPv4Address('10.0.0.0') + 65536 * num))
        # 定义B类地址
        self.class_b.append('172.16.0.0')
        for num in range(1, 16):
            self.class_b.append(str(IPv4Address('172.16.0.0') + 65536 * num))

        # 定义GoapAI的目标状态
        self.goal = {
            "GoalSymbol_GetLocalSecretInfo": True,
            "GoalSymbol_GetNwSecretInfo": True
        }
        # 定义GoapAI的初始状态
        self.state = {
            'Symbol_ProcessMigrate': None,
            'Symbol_ArpPoisoning': None,
            'Symbol_ValidUser': None,
            'Symbol_DCCheck': None,
            'Symbol_GetLanNodes': None,
            'Symbol_SearchMainDrive': None,
            'Symbol_CreateUser': None,
            'Symbol_SearchNwDrive': None,
            'Symbol_LateralMovement': None,
            'Symbol_DomainUser': None,
            'Symbol_MainDriveInfo': None,
            'Symbol_LogonUserInfo': None,
            'Symbol_TcpScan': None,
            'Symbol_UdpScan': None,
            'Symbol_GetNetworkInfo': None,
            'Symbol_NwDriveInfo': None,
            'Symbol_IdentOs': None,
            'Symbol_GetOsPatch': None,
            'GoalSymbol_GetLocalSecretInfo': None,
            'Symbol_ProcessInfo': None,
            'GoalSymbol_GetNwSecretInfo': None,
            'Symbol_PrivilegeEscalation': None,
            'Symbol_LocalUser': None
        }

        self.wjson = write_json.WriteJson()  # 用于向nodes.json文件写node信息

        self.wcsv = attack_tree.AttackTree()  # 用于向attack_tree.csv文件写攻击树信息
        self.pre_exe = None

        self.mylogger = MyLogger.MyLogger()  # 用于向moryson.log写入程序日志

    def plan_execute(self, goap_node, node_id, plan, target, node_num):
        print("plan = {}".format(plan))

        # 将计划写入moryson.log文件
        self.mylogger.writelog("action plan = " + pprint.pformat(plan, width=500, compact=True), "info")

        for p in plan:
            print("execute action = {}".format(p))

            if p == "arpscan":
                # 执行arpscan
                if target == self.local_ipaddr:
                    pre_node_id = node_id
                    arpscanInstance = arpscan.ArpScan()
                    node_id = arpscanInstance.execute_arpscan(self.node, self.link, node_id)
                    node_id += 1
                    self.node_json["nodee"] = self.node
                    self.node_json["links"] = self.link

                    if self.pre_exe == None:
                        self.wcsv.write(["name", "parent", "ip", "mitre"])
                        target = self.node[0]["id"]
                        print(target)

                    self.wcsv.write(
                        ["T1120 (arpscan) - " + self.node[0]["id"], self.pre_exe, self.node[0]["id"], "T1120"])
                    self.pre_exe = "T1120 (arpscan) - " + self.node[0]["id"]

                    self.wjson.write(self.node_json)

                else:
                    print("arpscan ip is not self")
                    exit()

            elif p == "tcpscan":
                mynmapInstance = mynmap.MyNmap()

                proxy = 0

                for num in range(pre_node_id, node_id, 1):
                    mynmapInstance.execute_nmap(self.node[num]["id"], num, self.node, proxy)

                if self.pre_exe == "T1120 (arpscan) - " + self.node[0]["id"]:  # If first tcpscan
                    self.wcsv.write(
                        ["T1046 (tcpscan) - " + self.node[0]["id"], self.pre_exe, self.node[0]["id"], "T1046, T1018"])
                    self.pre_exe = "T1046 (tcpscan) - " + self.node[0]["id"]

                    goap_node.state["Symbol_TcpScan"] = True
                    goap_node.state["Symbol_IdentOs"] = True
                    self.node[0]["goap"] = copy.deepcopy(goap_node.state)
                else:
                    self.wcsv.write(["T1046 (tcpscan) - " + target, self.pre_exe, target, "T1046, T1018"])

                    goap_node.state["Symbol_TcpScan"] = True
                    goap_node.state["Symbol_IdentOs"] = True
                    self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                print(target, num)
                self.wjson.write(self.node_json)

            elif p == "exploit_lateral":
                res = -1

                # Search local pass
                if res != 0:
                    for num in range(1, len(self.node)):
                        if len(self.node[num]["local_account_pass"]) > 0:  # 拥有该主机的密码
                            value = iter(self.node[num]["local_account_pass"])
                            print(value)
                            for account, password in zip(value, value):
                                exploit = msploit.MetaSploit()
                                # TO DO

                # search Linux exploit 
                if res != 0 and self.node[node_num]["os"] == "Linux":
                    exploit = msploit.MetaSploit()
                    res = exploit.execute_ssh_bruteforce(target, node_num, self.node)

                # search Windows exploit
                if res != 0 and self.node[node_num]["os"] == "Windows":
                    exploit = msploit.MetaSploit()
                    res = exploit.execute_eternalblue(target, node_num, self.node, self.local_ipaddr)

                # write log
                if res == 0:
                    goap_node.state["Symbol_LateralMovement"] = True
                    self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                    self.wcsv.write(["TA0008 (exploit_lateral) - " + target, self.pre_exe, target, "TA0008"])
                    self.pre_exe = "TA0008 (exploit_lateral) - " + target

                    self.wjson.write(self.node_json)
                else:
                    goap_node.state["Symbol_LateralMovement"] = False
                    self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                    self.wcsv.write(["TA0008 (exploit_lateral) - " + target, self.pre_exe, target, "TA0008"])
                    self.pre_exe = "TA0008 (exploit_lateral) - " + target

                    self.wjson.write(self.node_json)

                    # print("replanning...")

                    self.mylogger.writelog("replanning...", "info")

                    return node_id

            elif p == "get_networkinfo":
                exploit = msploit.MetaSploit()
                exploit.execute_ipconfig(node_num, self.node)

                exploit.execute_netstat(node_num, self.node)

                self.wcsv.write(["T1016(get_networkinfo) - " + target, self.pre_exe, target, "T1016, T1049"])

                goap_node.state["Symbol_GetNetworkInfo"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)

            elif p == "get_processinfo":
                exploit = msploit.MetaSploit()
                exploit.execute_ps(node_num, self.node)

                self.wcsv.write(["T1057 (get_processinfo) - " + target, self.pre_exe, target, "T1057, T1059"])

                goap_node.state["Symbol_ProcessInfo"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)

            elif p == "get_local_user":
                exploit = msploit.MetaSploit()
                exploit.execute_netuser(node_num, self.node)

                exploit.get_local_hash(node_num, self.node)
                exploit.get_local_pass(node_num, self.node)

                # get pass

                self.wcsv.write(["T1087 (get_local_user) - " + target, self.pre_exe, target, "T1087"])

                goap_node.state["Symbol_LocalUser"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)

            elif p == "get_domain_user":
                exploit = msploit.MetaSploit()
                exploit.execute_netuserdomain(node_num, self.node)

                # domain pass
                exploit.get_domain_pass(node_num, self.node)

                self.wcsv.write(["T1087 (get_domain_user) - " + target, self.pre_exe, target, "T1087"])

                goap_node.state["Symbol_DomainUser"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)

            elif p == "get_ospatch":
                exploit = msploit.MetaSploit()
                exploit.execute_getospatch(node_num, self.node)

                self.wcsv.write(["T1003 (get_ospatch) - " + target, self.pre_exe, target, "T1003, T1059, T1082"])

                goap_node.state["Symbol_GetOsPatch"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)



            elif p == "get_maindrvinfo":
                exploit = msploit.MetaSploit()
                secret_data = exploit.execute_getmaindrvinfo(node_num, self.node)

                self.wcsv.write(["T1083 (get_maindrvinfo) - " + target, self.pre_exe, target, "T1083, TA0009, TA0010"])

                goap_node.state["Symbol_MainDriveInfo"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)

            elif p == "get_netdrvinfo":
                exploit = msploit.MetaSploit()
                exploit.execute_netuse(node_num, self.node)

                self.wcsv.write(["T1083 (get_netdrvinfo) - " + target, self.pre_exe, target, "T1083, T1135"])

                goap_node.state["Symbol_NetDriveInfo"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)

            elif p == "get_local_secretinfo":
                exploit = msploit.MetaSploit()
                secret_data = exploit.execute_getlocalsecretinfo(node_num, self.node)

                self.wcsv.write(["TA0009 (get_local_secretinfo) - " + target, self.pre_exe, target, "TA0009"])

                if secret_data == 1:
                    goap_node.state["GoalSymbol_GetLocalSecretInfo"] = True
                else:
                    goap_node.state["GoalSymbol_GetLocalSecretInfo"] = False

                goap_node.state["Symbol_SearchMainDrive"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)

            elif p == "get_nw_secretinfo":
                secret_data = 0

                if len(self.node[node_num]["network_drive"]) > 0:
                    exploit = msploit.MetaSploit()
                    secret_data = exploit.execute_getnwsecretinfo(node_num, self.node)

                self.wcsv.write(["TA0009 (get_nw_secretinfo) - " + target, self.pre_exe, target, "TA0009"])

                if secret_data == 1:
                    goap_node.state["GoalSymbol_GetNwSecretInfo"] = True
                else:
                    goap_node.state["GoalSymbol_GetNwSecretInfo"] = False

                goap_node.state["Symbol_SearchNwDrive"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)

            elif p == "get_packetinfo":
                exploit = msploit.MetaSploit()

                if self.node[node_num]["os"] == "Windows":
                    exploit.execute_sniff_win(node_num, self.node)
                elif self.node[node_num]["os"] == "Linux":
                    exploit.execute_sniff_linux(node_num, self.node)

                self.wcsv.write(["T1040 (get_packetinfo) - " + target, self.pre_exe, target, "T1040"])

                goap_node.state["Symbol_PacketInfo"] = True
                self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

                self.wjson.write(self.node_json)




            else:
                print(p + "error")

    def select_target(self):
        print("select target")

        target_list = {}  # 用于存放尚未获取权限的目标
        performed_list = {}  # 用于存放已经获取权限，但未执行SearchMainDrive和SearchNwDrive的目标

        for num in range(1, len(self.node)):
            if self.node[num]["os"] == "Linux":
                # print("Linux")
                if self.node[num]["session"] == "" and self.node[num]["goap"]["Symbol_LateralMovement"] == None:
                    if len(self.node[num]["ports"]) > 0:
                        for port_num in range(0, len(self.node[num]["ports"])):
                            # if self.node[num]["ports"][port_num]["number"] == "22/tcp" and self.node[num]["ports"][port_num]["service"] == "ssh":
                            if self.node[num]["ports"][port_num]["number"] == "22/tcp" and \
                                    self.node[num]["ports"][port_num]["service"] == "ssh":
                                target_list[self.node[num]["id"]] = num
            else:
                if self.node[num]["goap"]["Symbol_SearchMainDrive"] == None or self.node[num]["goap"][
                    "Symbol_SearchNwDrive"] == None:
                    performed_list[self.node[num]["id"]] = num
            if self.node[num]["os"] == "Windows":
                print("windows")
                if self.node[num]["session"] == "" and self.node[num]["goap"]["Symbol_LateralMovement"] == None:
                    target_list[self.node[num]["id"]] = num
                else:
                    if self.node[num]["goap"]["Symbol_SearchMainDrive"] == None or self.node[num]["goap"][
                        "Symbol_SearchNwDrive"] == None:
                        performed_list[self.node[num]["id"]] = num

        print("target_list = {}".format(target_list))
        print("performed_list = {}".format(performed_list))

        if len(performed_list) != 0:
            target, node_num = random.choice(list(performed_list.items()))
            target_list.clear()
            performed_list.clear()
            # print("goap_state = {}".format(self.node[node_num]["goap"]))
            return target, node_num, self.node[node_num]["goap"]
        elif len(target_list) != 0:
            target, node_num = random.choice(list(target_list.items()))
            target_list.clear()
            performed_list.clear()
            # print("goap_state = {}".format(self.node[node_num]["goap"]))
            return target, node_num, self.node[node_num]["goap"]
        else:
            return None, None, None

    def goap_planning(self, goap_node):
        available_action = []
        plan = []

        self.mylogger.writelog("goap planning start...", "info")

        for i in range(100):
            print("\ntake = {}\n".format(i))

            if (goap_node.state["GoalSymbol_GetLocalSecretInfo"] == goap_node.goal["GoalSymbol_GetLocalSecretInfo"] or
                    goap_node.state["GoalSymbol_GetNwSecretInfo"] == goap_node.goal["GoalSymbol_GetNwSecretInfo"]):
                return plan
            for key in goap_node.actions.keys():
                match_count = 0
                for symbol, value in goap_node.actions[key]["precond"].items():
                    if (goap_node.state[symbol] == value):
                        match_count += 1
                if (match_count == len(goap_node.actions[key]["precond"])):
                    # available_action.append(key)

                    match_effect_count = 0
                    for symbol, value in goap_node.actions[key]["effect"].items():
                        if goap_node.state[symbol] == value:
                            match_effect_count += 1
                    if match_effect_count < len(goap_node.actions[key]["effect"]):
                        # print("match!!")
                        available_action.append(key)

            #   print("avaliable plan = " + pprint.pformat(available_action, width=500, compact=True), "info")
            self.mylogger.writelog("available plan = " + pprint.pformat(available_action, width=500, compact=True),
                                   "info")

            if (len(available_action) == 0):
                # print("No available action")
                self.mylogger.writelog("No available action", "info")
                exit(0)

            # currentry, use Dijkstra algorithm
            # A* or Dijkstra's algorithm or random
            tmp = 100
            tmp_list = []
            for key in available_action:
                if (goap_node.actions[key]["priority"] < tmp):
                    priority_key = key
                    tmp = goap_node.actions[key]["priority"]
                    tmp_list.clear()
                    tmp_list.append(priority_key)
                elif (goap_node.actions[key]["priority"] == tmp):
                    tmp_list.append(key)

            while (True):
                priority_key = random.choice(tmp_list)
                if priority_key not in plan:
                    break

            plan.append(priority_key)
            available_action.clear()

            for key, value in goap_node.actions[priority_key]["effect"].items():
                goap_node.state[key] = value

    def network_scan(self, node_id, goap_node):
        print("Starting a Network Scan...")
        self.mlogger.writelog("Starting a Network Scan...", "info")

        exploit = msploit.MetaSploit()
        # To do
        # exploit.execute_socks()

    def load_action(self, actionfile):
        with open(actionfile) as f:
            return json.load(f)

    def get_ipaddr(self):
        try:
            ipaddr = subprocess.check_output(
                'ifconfig ens33 | grep "inet " | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'',
                shell=True).decode('utf-8')
            # print(res)
            return ipaddr.replace('\n', '')
        except:
            print("get-ipaddr error!!")
