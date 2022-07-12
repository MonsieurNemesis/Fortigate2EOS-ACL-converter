from cmath import nan
from turtle import up
from numpy import NaN
import pandas as pd
from collections import defaultdict
import math
import json
from pprint import pprint


def file_reader(hosts, filename):
    temp_list = []
    # f = open("Access-List Cirrus copy.txt", "rt")
    f = open(filename, "rt")

    #  0 -> key !present
    flag = 0
    for idx, i in enumerate(f):
        for key in hosts:
            if key in i:
                for val in hosts[key]:
                    temp_list.append(i.replace(key, val))
                    flag = 1

        if flag == 0:
            temp_list.append(i)
        else:
            flag = 0
    # pprint(temp_list)
    file_writer(temp_list)


def file_writer(lines):
    f = open("hosts_substituted.txt", "w")
    for i in lines:
        f.write(i)


def hostname_dict_creator():
    df = pd.read_excel('hostnames.xlsx')
    new_dict = df.set_index('hostname').T.to_dict('list')
    updated_dict = defaultdict(dict)
    temp_list = []
    for i in new_dict:
        for j in new_dict[i]:
            if (isinstance(j, float) and math.isnan(j)):
                continue
            else:
                temp_list.append(j)
            # print(type(j), j)
        updated_dict[i.strip()] = temp_list
        temp_list = []
    return updated_dict


if __name__ == "__main__":
    hostname = hostname_dict_creator()
    file_reader(hosts=hostname, filename="new_CIRRUS_ACL.txt")
