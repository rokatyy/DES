import DES_standart
from format_operations import BinaryOperations


class Operations(BinaryOperations):
    def __init__(self):
        BinaryOperations.__init__(self)
        self.IP = DES_standart.IP
        self.IP_INV = DES_standart.IP_INV
        self.PC1 = DES_standart.PC1
        self.PC2 = DES_standart.PC2
        self.E = DES_standart.E
        self.P = DES_standart.P
        self.SHIFT = DES_standart.SHIFT
        self.S_BOX = DES_standart.Sboxes
        self.data = None
        self.keys = []
        self.result = []

    def encrypt(self, key):
        print('Encryption starts..')
        self.__pad()
        self.__generatekeys(key)
        text_blocks = self.nsplit(self.data, 8)
        self.result = []
        for block in text_blocks:
            block = self.str_to_binary_list(block)
            block = self.permutation_by_table(block, self.IP)
            g, d = self.nsplit(block, 32)
            for i in range(16):
                d_e = self.expand(d, self.E)
                tmp = self.xor(self.keys[i], d_e)
                tmp = self.substitute(tmp)
                tmp = self.permutation_by_table(tmp, self.P)
                tmp = self.xor(g, tmp)
                g = d
                d = tmp
            self.result += self.permutation_by_table(d + g,
                                                     self.IP_INV)
        self.result = self.binary_list_to_str(self.result)
        print(f"Encryption result:{self.result}")

    def decrypt(self, key):
        self.__generatekeys(key)
        text_blocks = self.nsplit(self.data, 8)
        self.result = []
        for block in text_blocks:
            block = self.str_to_binary_list(block)
            block = self.permutation_by_table(block, self.IP)
            g, d = self.nsplit(block, 32)
            for i in range(16):
                d_e = self.expand(d, self.E)
                tmp = self.xor(self.keys[15 - i], d_e)
                tmp = self.substitute(tmp)
                tmp = self.permutation_by_table(tmp, self.P)
                tmp = self.xor(g, tmp)
                g = d
                d = tmp
            self.result += self.permutation_by_table(d + g, self.IP_INV)
        self.data = self.binary_list_to_str(self.result)
        self.__unpad()
        print(f"Decryption result: {self.data}")

    def substitute(self, d_e):
        subblocks = self.nsplit(d_e, 6)
        result = list()
        for i in range(len(subblocks)):
            block = subblocks[i]
            row = int(str(block[0]) + str(block[5]), 2)
            column = int(''.join([str(x) for x in block[1:][:-1]]), 2)
            val = self.S_BOX[i][row][column]
            bin = self.binary(val, 4)
            result += [int(x) for x in bin]
        return result

    def permutation_by_table(self, block, table):
        return [block[x - 1] for x in table]

    def expand(self, block, table):
        return self.permutation_by_table(block, table)

    def xor(self, value1, value2):
        return [x ^ y for x, y in zip(value1, value2)]

    def __generatekeys(self, password):
        key = self.str_to_binary_list(password)
        key = self.permutation_by_table(key, self.PC1)
        g, d = self.nsplit(key, 28)
        for i in range(16):
            g, d = self.shift(g, d, self.SHIFT[i])
            self.keys.append(self.permutation_by_table(g + d, self.PC2))

    def shift(self, g, d, n):
        return g[n:] + g[:n], d[n:] + d[:n]

    def __pad(self):
        pad_len = 8 - (len(self.data) % 8)
        self.data += pad_len * chr(pad_len)

    def __unpad(self):
        pad_len = ord(self.data[-1])
        self.data = self.data[:-pad_len]


class Plaintext(Operations):
    def __init__(self, text):
        Operations.__init__(self)
        self.data = text


class EncData(Operations):
    def __init__(self, data):
        Operations.__init__(self)
        self.data = data


text = Plaintext('secretdatatext')
text.encrypt('secret_kKK')
s = text.result
enc = EncData(s)
enc.encrypt('secret_KKK')
print(text.result)
