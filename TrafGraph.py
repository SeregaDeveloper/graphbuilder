#!/usr/bin/python
import pandas as pand
import networkx as nx
import matplotlib.pyplot as plt
import sys
import os
users = []
G = nx.MultiDiGraph()
#---------------------------------------------------------
def File_Loader(filename ="nope"):
    """ Function which is load the dump """
    try:
        file = pand.read_csv(filename,sep=',')
    except:
        print("This file does not exist! \n")
    return file
#---------------------------------------------------------
def Get_Users(file_in):
    """ Function which is collect unique ip """
    for ip_addr in file_in['ip.src'] :
        if ip_addr not in users:
            # допилить фильтрацию
            users.append(ip_addr)
    for ip_addr in file_in['ip.dst']:
        if ip_addr not in users:
            users.append(ip_addr)
    return 0
#---------------------------------------------------------
def Get_Pairs(dump):
    """ Function which is determine hosts activity """
    tcpupdate = pand.concat([dump['ip.src'], dump['ip.dst']], axis=1)
    tcpupdate = pand.DataFrame(tcpupdate.groupby(['ip.src', 'ip.dst'])['ip.src'].count())
    tcpupdate = tcpupdate.rename(columns={'ip.src': 'Requests'})
    tcpupdate.to_csv('Dump_Stat.csv')
    return tcpupdate
#---------------------------------------------------------
def Make_Graph_Nodes():
    """ Function which is build the graph nodes """
    for i in users:
        G.add_node(i)
    print("\n Nodes succesfully added! \n")
    return 0
#---------------------------------------------------------
def Make_Graph_Edges():
    """ Function which is build the graph edges """
    stat_load = pand.read_csv('Dump_Stat.csv', sep=',')
    os.remove('Dump_Stat.csv')
    request_stat = pand.DataFrame(stat_load)
    for i in range (len(request_stat)):
        edge_a = request_stat.iloc[i, request_stat.columns.get_loc('ip.src')]
        print (edge_a)
        edge_b = request_stat.iloc[i, request_stat.columns.get_loc('ip.dst')]
        print(edge_b)
        weight_ab = request_stat.iloc[i, request_stat.columns.get_loc('Requests')]
        print(weight_ab)
        if (G.has_edge(str(edge_b), str(edge_a))) == True:
            for u, v, d in G.edges(data=True):
                if (u == str(edge_b) and v == str(edge_a)) or (u == str(edge_a) and v == str(edge_b)):
                    d['weight'] += weight_ab
        else:
            G.add_edge(str(edge_b), str(edge_a), weight=weight_ab, size=11300)
    print("\n Edges succesfully added! \n")
    return 0
#---------------------------------------------------------
def Draw_Graph():
    """ Function which is draw the graph"""
    pos = nx.circular_layout(G)
    edge_labels = {(u, v): d['weight'] for u, v, d in G.edges(data=True)}
    nx.draw_networkx_nodes(G, pos, node_size=2, node_color='green')
    nx.draw_networkx_edges(G, pos)
    nx.draw_networkx_labels(G, pos)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_color='r')
    plt.gcf().set_size_inches(21, 21)
    plt.axis('off')
    plt.savefig(f"{filename}.png")
    print(f"Check your graph in '{filename}.png' ")
    users = []
    return 0
#---------------------------------------------------------
if __name__ == "__main__":
    """ Main function """

    if len (sys.argv) == 1:
        print("Traffic analisys programm ")
        print("Usage: TrafficGraph.py [file.csv]  \n")
    elif len (sys.argv) == 2:
        print("Started succesfully...\n")
        filename, file_extension = os.path.splitext(str(sys.argv[1]))
        if file_extension == '.csv':
            loaded_dump = File_Loader(str(sys.argv[1]))
        elif file_extension == '.pcap' or file_extension == '.pcapng':
            os.system(f"bash ./pcap_to_csv.sh {str(sys.argv[1])};")
            loaded_dump = File_Loader("Yourdump.csv")
            os.remove("Yourdump.csv")
        else:
            print('Format is not supported')
            print('Supported format: .csv, .pcap, .pcapng')
        file = pand.DataFrame(loaded_dump)
        print(f"File {str(sys.argv[1])} Loaded succesfully \n")
        print("\n Transmissin statistic ")
        pairs = Get_Pairs(file)
        print(pairs)
        print("\n Founding IP addresses: ")
        Get_Users(file)
        print(users)
        print("\n The begining of dump: ")
        print(file.head())
        Make_Graph_Nodes()
        Make_Graph_Edges()
        Draw_Graph()
    else:
        print ("There are only 1 arg available, try again")
#------------------------------------------------------------
