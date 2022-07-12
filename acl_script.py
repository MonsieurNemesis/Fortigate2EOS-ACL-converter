# for saurabh ln 470

from curses import keyname
from textwrap import indent
from collections import Counter
from pprint import pprint
import numpy as np
import re
import json
import logging

services_dict = {'RDP': '', 'DCE-RPC': 'RPC', 'TCP_9100': '9100', 'SMB': '', 'UDP_1434': '1434', 'TCP_1494': '1494', 'TCP_2666': '2666', 'tcp_1812_1813': '', 'SNMP': '', 'TCP_2660': '2660', 'TCP-3269': '3269', 'TCP_48003': '48003', 'PING': '', 'UDP_135': '135', 'TCP-5722': '5722', 'TCP-9090': '9090', 'UDP_138': '138', 'RADIUS': '', 'UDP_137': '137',
                 'SMTP': '', 'TCP_49786': '49786', 'SYSLOG': '', 'TCP-5646': '5646', 'TCP-3268': '3268', 'TCP_48002': '48002', 'TCP-5647': '5647', 'SMB-UDP': 'UDP', 'ALL': '', 'ALL_ICMP': 'ICMP', 'HTTPS': '', 'HTTP': '', 'NTP': '', 'TCP-8530': '8530', 'TCP_1025': '1025', 'Windows-AD': 'AD', 'DNS': '', 'TCP_8833': '8833', 'MS-SQL': 'SQL', 'TCP_25000': '25000'}


def last_word(string):
    lis = list(string.split(" "))
    length = len(lis)
    return lis[length-1].strip(' "\'\t\r\n').lower()


def backslash_stripper(conf):
    conf = conf.split()
    conf_ = []
    for c in conf:
        conf_.append(c.strip(' "\'\t\r\n'))
    return conf_


def value_extractor(string, keyword):
    before_keyword, keyword, after_keyword = string.partition(keyword)
    return backslash_stripper(after_keyword)


def dic_creator(unique):
    new_dic = {}
    for i in unique:
        temp = re.split('[_-]', i)
        temp_dict = {}
        if len(temp) == 2:
            new_dic[i] = re.split('[_-]', i)[1]
        else:
            new_dic[i] = ""

    return(new_dic)


def file_ops(filename):
    f = open(filename, "rt")

    orig_file = []
    conf_dict = {}

    unique_list = []
    unique_src = []
    unique_dst = []

    counter = 0
    for each in f:
        if counter == 1:
            if not "next" in each:
                if "srcintf" in each:
                    srcintf = value_extractor(each, "srcintf")
                    conf_dict["srcintf"] = srcintf

                if "dstintf" in each:
                    dstintf = value_extractor(each, "dstintf")
                    conf_dict["dstintf"] = dstintf

                # check for action
                if "action" in each:
                    action_type = "permit" if last_word(
                        each) == "accept" else "deny"
                    conf_dict["action"] = action_type

                # check for tos
                if "service" in each:
                    tos = value_extractor(each, "service")
                    conf_dict["tos"] = tos
                    for i in tos:
                        unique_list.append(i)

                # check for src ip
                if "srcaddr" in each:
                    source = value_extractor(each, "srcaddr")
                    conf_dict["src"] = source
                    for i in source:
                        unique_src.append(i)

                # check for dest ip
                if "dstaddr" in each:
                    dest = value_extractor(each, "dstaddr")
                    conf_dict["dest"] = dest
                    for i in dest:
                        unique_dst.append(i)

        if "edit" in each:
            counter = 1
        if "next" in each:
            counter = 0
            orig_file.append(conf_dict)
            conf_dict = {}

    return orig_file, set(unique_list), set(unique_src), set(unique_dst)


def acl_creator(conf):
    f = open("new_CIRRUS_ACL.txt", "w")
    # f_ = open("new_CIRRUS_ACL_RAW.txt", "w")
    temp_str = ""

    interface_dict = {}
    temp_list = []

    for conf_ in conf:
        action = conf_["action"]
        for tos_ in conf_["tos"]:
            for src_ in conf_["src"]:
                for dst_ in conf_["dest"]:
                    for i in data[tos_]:
                        type = i["type"]
                        port = i["port"]
                        port_str = ""
                        # if port is available as a list, iterate through all values
                        if isinstance(port, list):
                            for p in port:
                                port_str += str(p) + " "
                        # Otherwise, port is a single value (type: string)
                        else:
                            port_str = port

                        if src_[:3] == "IP-":
                            s_ip = src_[3:]
                        elif src_ == "all":
                            s_ip = "any"
                        else:
                            s_ip = src_

                        if dst_[:3] == "IP-":
                            d_ip = dst_[3:]
                        elif dst_ == "all":
                            d_ip = "any"
                        else:
                            d_ip = dst_

                        if port != "":
                            temp_str += action+" "+type+" "

                            if(s_ip == "any"):
                                temp_str += s_ip+" "+type+" "

                            else:
                                temp_str += "host"+" "+s_ip+" "

                            if(d_ip == "any"):
                                temp_str += d_ip+" "

                            else:
                                temp_str += "host"+" "+d_ip+" "

                            temp_str += "eq"+" "+port_str+"\n"
                            temp_list.append(temp_str)

                        else:
                            temp_str += action+" "+type+" "

                            if(s_ip == "any"):
                                temp_str += s_ip+" "+type+" "

                            else:
                                temp_str += "host"+" "+s_ip+" "

                            if(d_ip == "any"):
                                temp_str += d_ip+" "

                            else:
                                temp_str += "host"+" "+d_ip+"\n"
                                temp_list.append(temp_str)

                        key_name = f"{conf_['srcintf'][0]} - {conf_['dstintf'][0]}"

                        if key_name in interface_dict:
                            val = interface_dict[key_name]
                            val.append(temp_list)
                            interface_dict[key_name] = val
                        else:
                            interface_dict[key_name] = temp_list
                        # f_.write(temp_str)
                        temp_list = []
                        temp_str = ""
    for k in interface_dict:
        f.write(k+"\n\n")
        for val in interface_dict[k]:
            if not isinstance(val, str):
                for v_ in val:
                    f.write(v_)

            else:
                f.write(val)


if __name__ == "__main__":
    # This contains the "service type" to port number mappings
    dict_file = open('scratch.json')
    data = json.load(dict_file)

    # Change according to the filename containing fortigate policy rules, and place it in the same folder as this code
    # NOTE: This file should contain ONLY policies,
    # for eg.
    # config firewall policy
    # edit 80
    #     set status disable
    #     set uuid 219458ac-d865-51ec-8296-820a78d3d53e
    #     set srcintf "T6_Outside_2207"
    #     set dstintf "SLB_Swift_2319"
    #     set action accept
    #     set srcaddr "all"
    #     set dstaddr "all"
    #     set schedule "always"
    #     set service "ALL"
    # next

    # We get a parsed output containing the following:
    # config_list: a list consiting of the policy information extracted as a dictionary
    # unique: a list consiting of the unique type of services (Used to identify the port numbers required for these services)
    # u_src: a list consiting of the unique source name (Used to identify which hosts exist as variables (eg, www.google.com) and need ip address)
    # u_dst: a list consiting of the unique destination names (Used to identify which hosts exist as variables (eg, www.google.com) and need ip address)
    config_list, unique, u_src, u_dst = file_ops("cleaned_FW_config.txt")

    # This creates the ACL separated by the unique source and destination interfaces and writes out to file
    acl_creator(config_list)
