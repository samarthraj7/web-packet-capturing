
from scapy.all import *
from collections import Counter
import plotly

packets = rdpcap('new.pcap')

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

xData=[]
yData=[]
for ip, count in cnt.most_common():
    xData.append(ip)
    yData.append(count)


plotly.offline.plot({
"data":[plotly.graph_objs.Bar(x=xData, y=yData)],
"layout":plotly.graph_objs.Layout(title="Source IP Occurrence",
xaxis=dict(title="Src IP"),
       yaxis=dict(title="Count"))})


dest=[]
for pkt in packets:
    if IP in pkt:
        try:
           dest.append(pkt[IP].dst)
        except:
            pass

cnt=Counter()

for ip in dest:
    cnt[ip] += 1

x1Data=[]
y1Data=[]
for ip, count in cnt.most_common():
    x1Data.append(ip)
    y1Data.append(count)


plotly.offline.plot({
"data":[plotly.graph_objs.Bar(x=x1Data, y=y1Data)],
"layout":plotly.graph_objs.Layout(title="Destination",
xaxis=dict(title="Dest IP"),
       yaxis=dict(title="Count"))})
