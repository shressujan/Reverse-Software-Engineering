import sys
import os
import requests
import time
import io
binaryninja_api_path = "/bin/binaryninja/python/"
sys.path.append(binaryninja_api_path)
import binaryninja
from binaryninja import PluginCommandContext, PluginCommand
from binaryninja import SymbolType, Symbol

#stuff goes here
if len(sys.argv) < 2:
    print("bad args\n")
    sys.exit(0)

bv = binaryninja.BinaryViewType.get_view_of_file(sys.argv[1])
hasCall = False
nmap ={}
list = []
graph = ""
for f in bv.functions:
    print("\"0x{0:x}".format(f.start)+"\""+"[label= \""+f.name+"\"]\n")
    nmap[f.name] = "\"0x{0:x}".format(f.start)+"\""
for ff in bv.functions:
    for i in ff.instructions:
        ins = i[0]
        addr = i[1]
        code = ""
        for j in range(len(ins)):
            if not str(ins[j]).isspace():
                if(str(ins[j]) == "call"):
                    code = "\""+str(ins[j+2])+"\""
                    if(code in nmap.values()):
                        graph += "\"0x{0:x}".format(ff.start)+"\""
                        graph += "->\""+code + "\"\n"
print(graph)
file = open("graph.dot", "w")
file.write("\ndiagraph{\n"+graph+"}")
file.close

