class BinaryOperations:
    def __init__(self, bitsize=8):
        self.bitsize = bitsize

    def str_to_binary_list(self, text):
        array = []
        for symbol in text:
            binvalue = self.binary(symbol)
            array.extend([int(x) for x in list(binvalue)])
        return array

    def binary_list_to_str(self, array):
        res = ''.join([chr(int(y, 2)) for y in [''.join([str(x) for x in _bytes]) for _bytes in self.nsplit(array, 8)]])
        return res

    def binary(self, val, bitsize=8):
        binvalue = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
        if len(binvalue) > bitsize:
            assert AssertionError("Binary value longer that specified size")
        while len(binvalue) < bitsize:
            binvalue = "0" + binvalue  # Add as many 0 as needed to get the wanted size
        return binvalue

    def nsplit(self, s, n):
        return [s[k:k + n] for k in range(0, len(s), n)]
