from datetime import datetime

traxis = ['172.27.70.102', '172.27.70.103', '172.27.70.104',
          '172.27.70.105', '172.27.70.106', '172.27.70.107',
          '172.27.70.108', '172.27.70.109', '172.27.70.110']

class PcapLine:
    def _split_2(self, str):
        split = str.split(" IP ")

        if len(split) == 2:
            self.time = split[0]
            # self.tos = split[1]
        else:
            raise ValueError("Cannot split {}".format(str))

    def _split_ip(self, str):
        split = str.split(" ")

        self.src_addr = ".".join(split[0].split(".")[:4])
        self.src_port = split[0].split(".")[4]

        self.dst_addr = ".".join(split[2].split(".")[:4])
        self.dst_port = split[2].split(".")[4].replace(":", "")

        self.flags = split[4]

    def get_time(self):
        return self.timestamp.strftime("%H:%M:%S")

    def get_key(self, with_port=False):
        key = None
        if self.vip_to_trx():
            key = self.src_addr
            if with_port:
                key += "." + self.src_port

        if self.trx_to_vip():
            key = self.dst_addr
            if with_port:
                key += "." + self.dst_port

        return key

    def _split_3(self, str):
        split = str.split(", ")
        self._split_ip(split[0])
        self.ack = ""
        self.win = ""
        self.seq = ""
        self.options = ""
        self.body = ""
        self.length = ""
        for val in split:
            if "ack " in val:
                self.ack = val
            if "seq " in val:
                self.seq = val
            if "win " in val:
                self.win = val
            if "options " in val:
                self.options = val
            if "length " in val:
                self.length = val

            if "length: " in val:
                self.body = val.replace("\n", "")

            if self.body == "":
                self.length = self.length.replace("\n", "")

    def __init__(self, str):

        split_line = str.split("    ")

        if len(split_line) == 2:

            self._split_2(split_line[0])
            self._split_3(split_line[1])

            self.timestamp = datetime.strptime(self.time, "%H:%M:%S.%f")
            self.forwarding_delay = 0
            self.retransmission = False
        else:
            print(split_line)
            exit()

    def box_to_vip(self):
        return True if self.dst_addr == '195.60.83.229' and self.src_addr not in traxis else False

    def vip_to_trx(self):
        return True if self.dst_addr in traxis else False

    def vip_to_box(self):
        return True if self.src_addr == '195.60.83.229' else False

    def trx_to_vip(self):
        return True if self.src_addr in traxis else False

    def to_box(self):
        return self.trx_to_vip() or self.vip_to_box()

    def from_box(self):
        return self.box_to_vip() or self.vip_to_trx()

    def __str__(self):
        return " ".join([str(self.timestamp.time()), self.src_addr, self.src_port, self.dst_addr, self.dst_port,
                         self.flags, self.ack, self.seq,
                         self.win, self.options, self.length, self.body,
                         str(self.retransmission), str(self.forwarding_delay)
                         ])

    def __eq__(self, other):

        if self.from_box():
            if self.src_addr != other.src_addr:
                return False

        if self.to_box():
            if self.dst_addr != other.dst_addr:
                return False

        if self.src_port != other.src_port:
            return False

        if self.dst_port != other.dst_port:
            return False

        if self.flags != other.flags:
            return False

        if self.seq != other.seq:
            return False

        if self.ack != other.ack:
            return False

        if self.win != other.win:
            return False

        if self.options != other.options:
            return False

        if self.body != other.body:
            return False

        return True

    def is_retransmission(self, obj):
        if self == obj:
            if self.from_box() and obj.from_box() and self.dst_addr == obj.dst_addr:
                return True

            if self.to_box() and obj.to_box() and self.src_addr == obj.src_addr:
                return True

            if self.to_box() != obj.to_box() or self.from_box() != obj.from_box():
                raise ValueError("Unexpected values detected {0} {0}".format(str(self), str(obj)))

        return False