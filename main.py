from goap import goap

import copy
import subprocess
import csv


def goap_write(arg, count):
    if count == 0:
        with open('goap_contents.csv', 'w') as f:
            pass
    else:
        with open('goap_contents.csv', 'a') as f:
            w = csv.writer(f)
            w.writerow(arg)


def get_ipaddr():
    try:
        # res = subprocess.check_output('ifconfig | grep -A3 ens33 | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'', shell=True).decode('utf-8')
        ipaddr = subprocess.check_output(
            'ifconfig ens33 | grep "inet " | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'',
            shell=True).decode('utf-8')
        netmask = subprocess.check_output(
            'ifconfig ens33 | grep "inet " | grep -oP \'netmask [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/netmask //\'',
            shell=True).decode('utf-8')
        # print(res)
        return ipaddr.replace('\n', ''), netmask.replace('\n', '')
    except:
        print("get-ipaddr error!!")


if __name__ == '__main__':

    print("goap start")

    node_id = 0

    actionfile = '/home/moryson/Desktop/project/actions-it.json'

    goap_node = goap.GoapSymbol(actionfile)

    count = 0

    while not (goap_node.state["GoalSymbol_GetLocalSecretInfo"] == goap_node.goal["GoalSymbol_GetLocalSecretInfo"] or
               goap_node.state["GoalSymbol_GetNwSecretInfo"] == goap_node.goal["GoalSymbol_GetNwSecretInfo"]):
        print("count = {}".format(count))

        if count == 0:  # 第一次运行，使用arpscan和tcpscan
            plan = ['arpscan', 'tcpscan']
            target, netmask = get_ipaddr()
            node_num = 0
        else:
            # 目标选择
            target, node_num, target_state = goap_node.select_target()

            if target == None:
                print("There is no target...")
                # 重新网络扫描,查看是否存在主机
                node_id = goap_node.network_scan(node_id, goap_node)
                target, node_num, target_state = goap_node.select_target()

                # 若没有主机,则结束
                if target == None:
                    print("After all, there is no target...")
                    exit(0)

            goap_node.state = copy.deepcopy(target_state)
            # planning
            plan = goap_node.goap_planning(goap_node)

            print(plan)

            # exit()
            # 将 goap_node 的状态复原
            goap_node.state = copy.deepcopy(target_state)

        print("target = {}".format(target))
        goap_node.plan_execute(goap_node, node_id, plan, target, node_num)
        count += 1

        print("node_id = {}".format(node_id))

        # goap 
        g_content = copy.deepcopy(plan)
        g_content.insert(0, target)
        goap_write(g_content, count)

        count += 1
        if count == 5:
            break
    exit(0)