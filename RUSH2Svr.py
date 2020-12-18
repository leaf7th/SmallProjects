import socket
import struct

LOCALHOST = "127.0.0.1"
RECV_SIZE = 1500
PAYLOAD_SIZE = 1464
KEY = 3
FLAGS = ["0010000", "1001000", "1000100", "0101000", "0100100"]
CHK_FLAGS = ["0010010", "1001010", "1000110", "0101010", "0100110"]
ENC_FLAGS = ["0010001", "1001001", "1000101", "0101001", "0100101"]
ENC_CHK_FLAGS = ["0010011", "1001011", "1000111", "0101011", "0100111"]

def str_to_bytes(string, pad=PAYLOAD_SIZE):
    b_str = string.encode("UTF-8")
    if pad is not None:
        for i in range(len(string), pad):
            b_str += b'\0'
    return b_str

def bytes_to_str(bytes):
    return bytes.rstrip(b'\x00').decode("UTF-8")


def get_free_port():
    con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    con.bind(('', 0))
    port = con.getsockname()[1]
    con.close()
    return port

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def compute_checksum(message):
    b_str = message.encode("UTF-8")
    if (len(b_str) % 2 == 1):
      b_str += b'\0'
    checksum = 0
    for i in range(0, len(b_str), 2):
        w = b_str[i] + (b_str[i+1] << 8)
        checksum = carry_around_add(checksum, w)
    return ~checksum & 0xffff

def encode(payload, key=KEY):
    result = ""
    for c in payload:
        result += chr((ord(c) + key) % 128)
    return result

def decode(payload, key=KEY):
    result = ""
    for c in payload:
        result += chr((ord(c) - key) % 128)
    return result

class Connection:

    def __init__(self, my_port):
        self._my_info = (LOCALHOST, my_port)
        self._cli_info = None
        self.header = {}
        self.rec_header ={}
        self.header["seq_num"] = 1
        self.con = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.con.bind(self._my_info)
        self.last_seq = 0
        self.last_sender_seq = 0
        self.data = {}
        self.pkt = {}
        self.chk = False
        self.enc = False

    def construct_pkt(self, data):
        pkt = bytearray()
        seq = struct.pack('!H', self.header["seq_num"])
        for i in seq:
            pkt.append(i)
        ack = struct.pack('!H', self.header["ack_num"])
        for i in ack:
            pkt.append(i)
        cks = struct.pack('!H', self.header["checksum"])
        for i in cks:
            pkt.append(i)
        reserved = "000000001"
        flags = f'{self.header["ACK"]}{self.header["NAK"]}{self.header["GET"]}{self.header["DAT"]}{self.header["FIN"]}{self.header["CHK"]}{self.header["ENC"]}{reserved}'
        encflags = struct.pack('!H', int(flags, 2))
        for i in encflags:
            pkt.append(i)
        for i in data:
            pkt.append(i)
        pkt = bytes(pkt)
        return pkt

    def recv_pkt(self):
        raw_data, add = self.con.recvfrom(PAYLOAD_SIZE)
        self.unpack_header(raw_data)
        self._cli_info = add
        data = bytes_to_str(raw_data[8:])
        return data

    def send_pkt(self, pkt):
        self.last_seq = self.header["seq_num"]
        self.last_sender_seq = self.header["sender_seq"]
        self.con.sendto(pkt, self._cli_info)
        print(f"send:\n{self.header}")
        self.pkt[self.header["seq_num"]] = pkt
        self.header["seq_num"] = self.header["seq_num"] + 1
        print("\n\n\n\n")

    def send_data(self, data):
        if self.enc == True:
            data = encode(data)
        if self.chk == True:
            self.header["checksum"] = compute_checksum(data)
        senddata = str_to_bytes(data)
        pkt = self.construct_pkt(senddata)
        self.send_pkt(pkt)

    def close(self):
        self.con.close()

    def pre_send_data(self):
        self.header["ack_num"] = 0
        self.header["ACK"] = "0"
        self.header["NAK"] = "0"
        self.header["GET"] = "0"
        self.header["DAT"] = "1"
        self.header["FIN"] = "0"
        self.header["CHK"] = "0"
        if self.chk == True:
            self.header["CHK"] = "1"
        self.header["ENC"] = "0"
        if self.enc == True:
            self.header["ENC"] = "1"

    def retransmission(self):
        print(f"retransmission")
        self.header["seq_num"] -= 1
        self.send_pkt(self.pkt[self.header["seq_num"]])


    def data_split(self):
        i = 1
        while len(self.data[0]) > PAYLOAD_SIZE:
            self.data[i] = self.data[0][:PAYLOAD_SIZE]
            self.data[0] = self.data[0][PAYLOAD_SIZE:]
            i+=1
        self.data[i] = self.data[0]

    def unpack_header(self, data):
        self.header["sender_seq"] = int.from_bytes(data[:2], byteorder='big')
        self.header["ack_num"] = int.from_bytes(data[2:4], byteorder='big')
        self.header["checksum"] = int.from_bytes(data[4:6], byteorder='big')
        flags = "{:016b}".format(int.from_bytes(data[6:8], byteorder='big'))
        self.header["flags"] = flags
        self.header["ACK"] = flags[0]
        self.header["NAK"] = flags[1]
        self.header["GET"] = flags[2]
        self.header["DAT"] = flags[3]
        self.header["FIN"] = flags[4]
        self.header["CHK"] = flags[5]
        self.header["ENC"] = flags[6]
        self.rec_header = self.header.copy()

    def run(self):
        while True:
            try:
                data = self.recv_pkt()
                self.con.settimeout(4)
                require = self.header["ack_num"] + 1
                print(data)
                # Validation
                rec_flags = f'{self.rec_header["ACK"]}{self.rec_header["NAK"]}{self.rec_header["GET"]}{self.rec_header["DAT"]}{self.rec_header["FIN"]}{self.rec_header["CHK"]}{self.rec_header["ENC"]}'
                test_flags = f'{self.header["ACK"]}{self.header["NAK"]}{self.header["GET"]}{self.header["DAT"]}{self.header["FIN"]}{self.header["CHK"]}{self.header["ENC"]}'
                print(f"rec:{rec_flags}")
                print(f"test_fl:{test_flags}")
                if self.header["CHK"] == "1":
                    self.chk = True
                if self.header["ENC"] == "1":
                    self.enc = True
                print("last:" + str(self.last_sender_seq))
                print("seq:" + str(self.header["sender_seq"]))
                if self.last_sender_seq + 1 != self.header["sender_seq"]:
                    self.header["sender_seq"] = self.last_sender_seq
                    self.retransmission()
                elif self.last_seq != self.header["ack_num"]:
                    self.header["sender_seq"] = self.last_sender_seq
                    self.retransmission()
                elif self.header["sender_seq"] != 1 and self.header["GET"] == "1":
                    self.header["sender_seq"] = self.last_sender_seq
                    self.retransmission()
                # Checksum Validation
                elif self.chk == True and self.header["checksum"] != compute_checksum(data) and ((rec_flags in CHK_FLAGS[1:]) or (rec_flags in ENC_CHK_FLAGS[1:])):
                        self.header["sender_seq"] = self.last_sender_seq
                        self.retransmission()
                # Get
                elif rec_flags == "0010000":
                    f = open(data, "r")
                    self.data[0] = f.read()
                    f.close()
                    if len(self.data[0]) <= PAYLOAD_SIZE:
                        self.data[1] = self.data[0]
                        self.send_data(self.data[1])
                    else:
                        self.data_split()
                        self.pre_send_data()
                        self.send_data(self.data[1])
                # Check Get
                elif rec_flags == "0010010":
                    self.chk = True
                    if self.header["checksum"] != compute_checksum(data):
                        return
                    else:
                        f = open(data, "r")
                        self.data[0] = f.read()
                        f.close()
                        if len(self.data[0]) <= PAYLOAD_SIZE:
                            self.data[1] = self.data[0]
                            self.send_data(self.data[1])
                        else:
                            self.data_split()
                            self.pre_send_data()
                            self.send_data(self.data[1])

                # ENC Get
                elif rec_flags == "0010001":
                    self.enc = True
                    data = decode(data)
                    try:
                        f = open(data, "r")
                        self.data[0] = f.read()
                        f.close()
                    except:
                        self.header["ack_num"] = 0
                        self.header["ACK"] = "0"
                        self.header["NAK"] = "0"
                        self.header["GET"] = "0"
                        self.header["DAT"] = "0"
                        self.header["FIN"] = "1"
                        self.send_data("")
                    else:
                        if len(self.data[0]) <= PAYLOAD_SIZE:
                            self.data[1] = self.data[0]
                            self.send_data(self.data[1])
                        else:
                            self.data_split()
                            self.pre_send_data()
                            self.send_data(self.data[1])
                # ENC_CHK Get
                elif rec_flags == "0010011":
                    self.chk = True
                    self.enc = True
                    data = decode(data)
                    f = open(data, "r")
                    self.data[0] = f.read()
                    f.close()
                    if len(self.data[0]) <= PAYLOAD_SIZE:
                        self.data[1] = self.data[0]
                        self.send_data(self.data[1])
                    else:
                        self.data_split()
                        self.pre_send_data()
                        self.send_data(self.data[1])
                #  Flags Validation
                elif self.chk == False and self.enc == False and rec_flags not in FLAGS:
                    self.header["sender_seq"] = self.last_sender_seq
                    self.retransmission()
                elif self.chk == True and self.enc == False and rec_flags not in CHK_FLAGS:
                    self.header["sender_seq"] = self.last_sender_seq
                    self.retransmission()
                elif self.chk == False and self.enc == True and rec_flags not in ENC_FLAGS:
                    self.header["sender_seq"] = self.last_sender_seq
                    self.retransmission()
                elif self.chk == True and self.enc == True and rec_flags not in ENC_CHK_FLAGS:
                    self.header["sender_seq"] = self.last_sender_seq
                    self.retransmission()
                #  Data continue
                elif self.header["ACK"] == "1" and self.header["DAT"] == "1" and self.header["ack_num"] == self.last_seq and (require in self.data.keys()):
                    self.pre_send_data()
                    self.send_data(self.data[require])
                # NAK
                elif self.header["ACK"] == "0" and self.header["NAK"] == "1" and self.header["DAT"] == "1" and (self.header["ack_num"] in self.data.keys()):
                    self.retransmission()
                # FIN
                elif self.header["ACK"] == "1" and self.header["DAT"] == "1" and self.header["ack_num"] == self.last_seq and (require not in self.data.keys()):
                    self.header["ack_num"] = 0
                    self.header["ACK"] = "0"
                    self.header["NAK"] = "0"
                    self.header["GET"] = "0"
                    self.header["DAT"] = "0"
                    self.header["FIN"] = "1"
                    self.send_data("")
                elif self.header["ACK"] == "1" and self.header["FIN"] == "1" and self.header["ack_num"] == self.last_seq:
                    self.header["ack_num"] = self.header["sender_seq"]
                    self.header["ACK"] = "1"
                    self.header["NAK"] = "0"
                    self.header["GET"] = "0"
                    self.header["DAT"] = "0"
                    self.header["FIN"] = "1"
                    self.send_data("")
                    self.chk = False
                    self.enc = False
                    return
            except socket.timeout:
                print("succsee")
                self.retransmission()

if __name__ == '__main__':
    port = get_free_port()
    print(port, flush=True)
    con = Connection(port)
    con.run()
    con.close()