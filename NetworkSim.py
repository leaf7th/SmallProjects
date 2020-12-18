import sys
import ipaddress
import socket
import threading
import math
import random


def splitcmd(cmd):
    cmdlist = cmd.split()
    if cmdlist[0] == "msg":
        cmdlist = cmd.split(" ", 2)
    return cmdlist

def packet(string, sip, dip, id):
    data = bytearray(string, "UTF-8")
    header01 = b"\x45\x00"
    length = len(data) + 20
    blength = bytearray.fromhex("{:04x}".format(length))
    header23 = blength
    header45 = bytearray.fromhex("{:04x}".format(id))
    header67 = b"\x00\x00"
    header89 = b"\x40\x00"
    headerab = b"\x00\x00"
    sourceIP = ipaddress.ip_address(sip)
    bsourceIP = (int(sourceIP)).to_bytes(length=4, byteorder="big")
    desIP = ipaddress.ip_address(dip)
    bdesIP = (int(desIP)).to_bytes(length=4, byteorder="big")

    header = header01 + header23 + header45 + header67 + header89 + headerab + bsourceIP + bdesIP
    packet = header + data
    return packet

def fragpacket(string, sip, dip, id, flag, offset):
    data = bytearray(string, "UTF-8")
    header01 = b"\x45\x00"
    length = len(data) + 20
    blength = bytearray.fromhex("{:04x}".format(length))
    header23 = blength
    header45 = bytearray.fromhex("{:04x}".format(id))
    header67 = bytearray.fromhex("{:04x}".format(int("{:03b}".format(flag) + "{:013b}".format(offset),2)))
    header89 = b"\x40\x00"
    headerab = b"\x00\x00"
    sourceIP = ipaddress.ip_address(sip)
    bsourceIP = (int(sourceIP)).to_bytes(length=4, byteorder="big")
    desIP = ipaddress.ip_address(dip)
    bdesIP = (int(desIP)).to_bytes(length=4, byteorder="big")

    header = header01 + header23 + header45 + header67 + header89 + headerab + bsourceIP + bdesIP
    packet = header + data
    return packet

def debugpacket(string, sip, dip, id, flag, offset, ptl):
    data = bytearray(string, "UTF-8")
    header01 = b"\x45\x00"
    length = len(data) + 20
    blength = bytearray.fromhex("{:04x}".format(length))
    header23 = blength
    header45 = bytearray.fromhex("{:04x}".format(id))
    header67 = bytearray.fromhex("{:04x}".format(int("{:03b}".format(flag) + "{:013b}".format(offset),2)))
    header8 = b"\x40"
    header9 = bytearray.fromhex("{:02x}".format(ptl))
    headerab = b"\x00\x00"
    sourceIP = ipaddress.ip_address(sip)
    bsourceIP = (int(sourceIP)).to_bytes(length=4, byteorder="big")
    desIP = ipaddress.ip_address(dip)
    bdesIP = (int(desIP)).to_bytes(length=4, byteorder="big")

    header = header01 + header23 + header45 + header67 + header8 + header9 + headerab + bsourceIP + bdesIP
    packet = header + data
    return packet

def losspacket(string, sip, dip, id):
    data = bytearray(string, "UTF-8")
    header01 = b"\x45\x00"
    length = len(data) + 20
    blength = bytearray.fromhex("{:04x}".format(length))
    header23 = blength
    header45 = bytearray.fromhex("{:04x}".format(id))
    header67 = b"\x00\x00"
    header89 = b"\x40\x72"
    headerab = b"\x00\x00"
    sourceIP = ipaddress.ip_address(sip)
    bsourceIP = (int(sourceIP)).to_bytes(length=4, byteorder="big")
    desIP = ipaddress.ip_address(dip)
    bdesIP = (int(desIP)).to_bytes(length=4, byteorder="big")

    header = header01 + header23 + header45 + header67 + header89 + headerab + bsourceIP + bdesIP
    packet = header + data
    return packet

def unpacket(raw):
    data = {}
    data["id"] = int.from_bytes(raw[4:6], "big")
    data["flag_offset"] = "{:016b}".format(int.from_bytes(raw[6:8], "big"))
    data["flag"] = int(data["flag_offset"][2])
    data["offset"] = int(data["flag_offset"][3:],2)
    data["ptl"] = "{:02x}".format(int.from_bytes(raw[9:10], "big"))
    data["sip"] = ipaddress.ip_address(int.from_bytes(raw[12:16], "big")).exploded
    data["dip"] = ipaddress.ip_address(int.from_bytes(raw[16:20], "big")).exploded
    data["payload"] = raw[20:].decode("UTF-8")
    return data

def send(port, pkt, re=False):
    con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = ("localhost", port)
    con.sendto(pkt, addr)
    info = unpacket(pkt)

    if int(info['ptl'],16) == 114:
        fraglist[info["id"]] = []

    if debug[0] == True:
        print("\b\b**************** debug information ***************")
        print(f"Send a packet")
        print(f"Packet infomation: ")
        print(f"id: {info['id']}")
        print(f"flag: {info['flag']}")
        print(f"offset: {info['offset']}")
        print(f"ptl: {int(info['ptl'],16)}")
        print(f"sip: {info['sip']}")
        print(f"dip: {info['dip']}")
        print(f"payload: {info['payload']}")
        print(f"resend: {re}")
        print("**************** debug information end ***********\n")
    con.close()

def sendpacket(id, payload, ip, dip, re=False):
    target = ipaddress.ip_address(dip)
    sendtarget = dip
    if target not in net:
        if gateway[0]:
            sendtarget = gateway[0]
            if debug[0] == True:
                print("======= True des IP ======")
                print(dip)
                print("======= True des IP ======\n")
        else:
            print("No gateway found")
            return False
    if sendtarget not in arpmap.keys():
        if debug[0] == True:
            print("======= Not in map ======")
            print(dip)
            print("======= Not in map ======\n")
        print("No ARP entry found")
        return False
    if len(payload) <= mtu[0] - 20:
        pkt = packet(payload, ip, dip, id)
        send(int(arpmap[sendtarget]), pkt, re)
    else:
        maxpayload = mtu[0] - 20
        num = math.ceil(len(payload) / maxpayload)
        i = 0
        while i < num:
            if i < (num - 1):
                pkt = fragpacket(payload[i * maxpayload:(i + 1) * maxpayload], ip, dip, id, 1, i * maxpayload)
                send(int(arpmap[sendtarget]), pkt, re)
            elif i == (num - 1):
                pkt = fragpacket(payload[i * maxpayload:(i + 1) * maxpayload], ip, dip, id,
                                 0, i * maxpayload)
                send(int(arpmap[sendtarget]), pkt, re)
            i += 1
    return True

def recieveloss(info):
    pkt = losspacket("", info["dip"], info["sip"], info["id"])
    send(int(arpmap[info["sip"]]), pkt)

def expire(id):
    expiredinfo = sendlist.pop(id)
    if debug[0] == True:
        print("\b\b**************** debug information ***************")
        print(f"Del a packet")
        print(f"Packet infomation: ")
        print(f"id: {expiredinfo['id']}")
        print(f"sip: {expiredinfo['sip']}")
        print(f"dip: {expiredinfo['dip']}")
        print(f"payload: {expiredinfo['payload']}")
        print("**************** debug information end ***********\n")
    return

def recieve(port):
    conr = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = ("localhost", port)
    conr.bind(addr)
    while True:
        data,add = conr.recvfrom(4096)
        info = unpacket(data)
        if debug[0] == True:
            print("\b\b**************** debug information ***************")
            print(f"Recieve a packet")
            print(f"Packet infomation: ")
            print(f"id: {info['id']}")
            print(f"flag: {info['flag']}")
            print(f"offset: {info['offset']}")
            print(f"ptl: {int(info['ptl'],16)}")
            print(f"sip: {info['sip']}")
            print(f"dip: {info['dip']}")
            print(f"payload: {info['payload']}")
            print("**************** debug information end ***********\n")
        if info["id"] in fraglist.keys():
            fraglist[info["id"]].append(info)
        else:
            fraglist[info["id"]] = []
            fraglist[info["id"]].append(info)
            if info["flag"] == 1:
                timer = threading.Timer(frto[0], recieveloss, [info, ])
                timer.start()
                timerlist[info["id"]] = timer
        if info["flag"] == 1:
            continue
        else:
            if info["id"] in timerlist.keys():
                timerlist[info["id"]].cancel()
            payload = ""
            offsetmap = {}
            for i in fraglist[info["id"]]:
                offsetmap[i["offset"]] = i["payload"]
            loss = False
            offsetlist = sorted(offsetmap.keys())
            if debug[0] == True:
                print("\n========= offset list ===========")
                print(f"{offsetlist}")
                print("========= offset list ===========\n")
            for i in range(1, len(offsetlist)):
                if offsetlist[i] - offsetlist[i-1] != mtu[0]-20:
                    loss = True
                if debug[0] == True:
                    print(f"calu {i}: {offsetlist[i]} - {offsetlist[i-1]} = {offsetlist[i] - offsetlist[i-1]}")
            if loss == True:
                recieveloss(info)
            else:
                for i in offsetlist:
                    payload += offsetmap[i]
                if int(info["ptl"],16) == 0:
                    print(f'\b\bMessage received from {info["sip"]}: "{payload}"', flush=True)
                else:
                    print(f'\b\bMessage received from {info["sip"]} with protocol 0x{info["ptl"]}', flush=True)

                    if int(info["ptl"],16) == 114:
                        badre = True
                        if info["id"] in sendlist.keys():
                            badre = False
                        if badre == True:
                            print(f'Message-Resend received from {info["sip"]} for id 0x{"{:04x}".format(info["id"])} BAD', flush=True)
                        else:
                            resendinfo = sendlist[info["id"]]
                            sendpacket(resendinfo["id"], resendinfo["payload"], resendinfo["sip"], resendinfo["dip"], True)
                            print(f'Message-Resend received from {info["sip"]} for id 0x{"{:04x}".format(info["id"])}', flush=True)
                print("> ", end="", flush=True)

def main(argv):
    if len(argv) <= 2:
        print("Usage: python3 NetworkSim.py IP-addr LL-addr")
        return
    ipaddr = argv[1]
    ip = ipaddr.split("/")[0]
    lladdr = argv[2]


    t = threading.Thread(target=recieve, args=(int(lladdr),))
    t.start()

    while True:
        cmd = input("> ")
        if cmd:
            cmdlist = splitcmd(cmd)
            if cmdlist[0] == "exit":
                return

            elif cmdlist[0] == "test":
                print("test")

            elif cmdlist[0] == "gw":
                if cmdlist[1] == "set":
                    gateway[0] = cmdlist[2]
                elif cmdlist[1] == "get":
                    print(gateway[0])

            elif cmdlist[0] == "arp":
                if cmdlist[1] == "set":
                    arpmap[cmdlist[2]] = cmdlist[3]
                    # t = threading.Thread(target=recieve, args=(int(cmdlist[3]),))
                    # t.start()
                elif cmdlist[1] == "get":
                    if cmdlist[2] in arpmap.keys():
                        print(arpmap[cmdlist[2]])
                    else:
                        print(None)

            elif cmdlist[0] == "msg":
                payload = cmdlist[2][1:-1]
                id = random.randint(0, 65535)
                while id in randomlist:
                    id = random.randint(0, 65535)
                sendresult = sendpacket(id, payload, ip, cmdlist[1])
                if sendresult == True:
                    pktinfo = {}
                    pktinfo["id"] = id
                    pktinfo["sip"] = ip
                    pktinfo["dip"] = cmdlist[1]
                    pktinfo["payload"] = payload
                    sendlist[id] = pktinfo
                    timer = threading.Timer(3 * frto[0], expire, [id, ])
                    timer.start()
                    expiretimer[id] = timer

                # target = ipaddress.ip_address(cmdlist[1])
                # if target in net:
                #     if cmdlist[1] in arpmap.keys():
                #         payload = cmdlist[2][1:-1]
                #         id = random.randint(0,65535)
                #         while id in randomlist:
                #             id = random.randint(0,65535)
                #         sendpacket(id, payload, ip, cmdlist[1])
                #         pktinfo = {}
                #         pktinfo["id"] = id
                #         pktinfo["sip"] = ip
                #         pktinfo["dip"] = cmdlist[1]
                #         pktinfo["payload"] = payload
                #         sendlist[id] = pktinfo
                #         timer = threading.Timer(3*frto[0], expire, [id, ])
                #         timer.start()
                #         expiretimer[id] = timer
                #
                #     else:
                #         print("No ARP entry found")
                # else:
                #     if gateway[0]:
                #         if gateway[0] in arpmap.keys():
                #             id = random.randint(0, 65535)
                #             while id in randomlist:
                #                 id = random.randint(0, 65535)
                #             payload = cmdlist[2][1:-1]
                #             sendpacket(id, payload, ip, gateway[0])
                #             pktinfo = {}
                #             pktinfo["id"] = id
                #             pktinfo["sip"] = ip
                #             pktinfo["dip"] = cmdlist[1]
                #             pktinfo["payload"] = payload
                #             sendlist[id] = pktinfo
                #             timer = threading.Timer(3 * frto[0], expire, [id, ])
                #             timer.start()
                #             expiretimer[id] = timer
                #             # print(f"send to {gateway}")
                #         else:
                #             print("No ARP entry found")
                #     else:
                #         print("No gateway found")

            elif cmdlist[0] == "mtu":
                if cmdlist[1] == "set":
                    mtu[0] = int(cmdlist[2])
                elif cmdlist[1] == "get":
                    print(mtu[0])

            elif cmdlist[0] == "frto":
                if cmdlist[1] == "set":
                    frto[0] = int(cmdlist[2])
                elif cmdlist[1] == "get":
                    print(frto[0])

            elif cmdlist[0] == "debug":
                string = cmdlist[1]
                sip = cmdlist[2]
                dip = cmdlist[3]
                id = int(cmdlist[4])
                flag = int(cmdlist[5])
                offset = int(cmdlist[6])
                ptl = int(cmdlist[7])
                pkt = debugpacket(string, sip, dip, id, flag, offset,ptl)
                send(int(arpmap[dip]),pkt)
                if debug[0] == True:
                    print("\b\b**************** debug information ***************")
                    print(f"Sendlist infomation: ")
                    i = 0
                    for si in sendlist.values():
                        i += 1
                        print(f"=== packet {i} ===")
                        print(f"id: {si['id']}")
                        print(f"sip: {si['sip']}")
                        print(f"dip: {si['dip']}")
                        print(f"payload: {si['payload']}")
                    print("**************** debug information end ***********\n")

            elif cmdlist[0] == "sendlist":
                if cmdlist[1] == "get":
                    print("\b\b**************** debug information ***************")
                    print(f"Sendlist infomation: ")
                    i = 0
                    for si in sendlist.values():
                        i += 1
                        print(f"=== packet {i} ===")
                        print(f"id: {si['id']}")
                        print(f"sip: {si['sip']}")
                        print(f"dip: {si['dip']}")
                        print(f"payload: {si['payload']}")
                    print("**************** debug information end ***********\n")


if __name__ == '__main__':
    fraglist = {}
    arpmap = {}
    sendlist = {}
    frto = [5]
    timerlist = {}
    expiretimer = {}
    randomlist = []
    mtu = [1500]
    gateway = [None]
    debug = [False]
    net = ipaddress.ip_network(sys.argv[1], strict=False)
    if len(sys.argv) > 3 and sys.argv[3] == "debug":
        debug[0] = True
        print("DEBUG MODE")
        mtu = [100]
        arpmap["192.168.1.1"] = "1111"
        arpmap["192.168.1.2"] = "2222"
        arpmap["192.168.1.3"] = "3333"
    main(sys.argv)
