from re import A
from scapy.all import *
from collections import Counter
from prettytable import PrettyTable
import plotly
import pyx

packets = rdpcap('new.pcap')

#print(pkt[IP].src)
srcIP=[]
for pkt in packets:
    if IP in pkt:
        try:
           srcIP.append(pkt[IP].src)
        except:
            pass

cnt=Counter()

for ip in srcIP:
    cnt[ip] += 1


table= PrettyTable(["IP", "Count"])

for ip, count in cnt.most_common():
   table.add_row([ip, count])

print(table)



destIP=[]
for pkt in packets:
    if IP in pkt:
        try:
           destIP.append(pkt[IP].dst)
        except:
            pass

cnt=Counter()

for ip in destIP:
    cnt[ip] += 1


table1= PrettyTable(["IP_DEST", "Count"])

for ip, count in cnt.most_common():
   table1.add_row([ip, count])

print(table1)


portip=[]
for pkt in packets:
    if IP in pkt:
        try:
           portip.append(pkt[IP].sport)
        except:
            pass

cnt=Counter()

for ip in portip:
    cnt[ip] += 1


table2= PrettyTable(["port", "Count"])

for ip, count in cnt.most_common():
   table2.add_row([ip, count])

print(table2)


dportip=[]
for pkt in packets:
    if IP in pkt:
        try:
           dportip.append(pkt[IP].dport)
        except:
            pass

cnt=Counter()

for ip in dportip:
    cnt[ip] += 1


table3= PrettyTable(["dport", "Count"])

for ip, count in cnt.most_common():
   table3.add_row([ip, count])

print(table3)