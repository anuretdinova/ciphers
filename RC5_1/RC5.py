class RC5:

    # Инициализация необходимых стартовых переменных
    def __init__(self, w, X, key):
        self.w = w
        self.X = X
        self.key = key
        self.Y = 2 * (X + 1)
        self.w4 = w // 4
        self.w8 = w // 8
        self.mod = 2 ** self.w
        self.mask = self.mod - 1
        self.b = len(key)

        self.__keyAlign()
        self.__keyExtend()
        self.__shuffle()

    # Константы
    def __const(self):  # функция генерации констант
        if self.w == 16:
            return (0xB7E1, 0x9E37)  # Возвращает значения P и Q соответсвенно
        elif self.w == 32:
            return (0xB7E15163, 0x9E3779B9)
        elif self.w == 64:
            return (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)

    # Если размер ключа(в байтах) не кратен w/8, дополняем его нулевыми байтами до ближайшего размера кратного w/8
    def __keyAlign(self):
        if self.b == 0:  # пустой ключ
            self.c = 1
        elif self.b % self.w8:  # ключ не кратен w / 8
            self.key += b'\x00' * (self.w8 - self.b % self.w8)  # дополняем ключ байтами
            self.b = len(self.key)
            self.c = self.b // self.w8
        else:
            self.c = self.b // self.w8
        L = [0] * self.c
        for i in range(self.b - 1, -1, -1):  # Заполняем массив L
            L[i // self.w8] = (L[i // self.w8] << 8) + self.key[i]
        self.L = L

    def __keyExtend(self):  # Заполняем массив M
        X, Z = self.__const()
        self.M = [(X + i * Z) % self.mod for i in range(self.Y)]

    # Циклический сдвиг влево
    def __lshift(self, value, k):
        k %= self.w
        return ((value << k) & self.mask) | ((value & self.mask) >> (self.w - k))

    # Циклический сдвиг вправо
    def __rshift(self, value, k):
        k %= self.w
        return ((value & self.mask) >> k) | (value << (self.w - k) & self.mask)

    # Перемешивание массивов L и M
    def __shuffle(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.Y)):
            A = self.M[i] = self.__lshift((self.M[i] + A + B), 3)
            B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)
            i = (i + 1) % self.Y
            j = (j + 1) % self.c

    # Шифрование
    def encryptPart(self, data):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        A = (A + self.M[0]) % self.mod
        B = (B + self.M[1]) % self.mod
        for i in range(1, self.X + 1):
            A = (self.__lshift((A ^ B), B) + self.M[2 * i]) % self.mod
            B = (self.__lshift((A ^ B), A) + self.M[2 * i + 1]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def encryptFile(self, inputFileName, outputFileName):  # имя входного и выходного файлов
        with open(inputFileName, 'rb') as inp, open(outputFileName, 'wb') as out:
            run = True
            while run:
                text = inp.read(self.w4)
                if not text:
                    break
                if len(text) != self.w4:  # дополняем  нулевыми байтами
                    text = text.ljust(self.w4, b'\x00')
                    run = False
                text = self.encryptPart(text)
                out.write(text)

    def encryptBytes(self, data):
        res, run = b'', True
        while run:
            temp = data[:self.w4]
            if len(temp) != self.w4:
                data = data.ljust(self.w4, b'\x00')
                run = False
            res += self.encryptPart(temp)
            data = data[self.w4:]
            if not data:
                break
        return res

    # Дешифрование
    def decryptBlock(self, data):
        A = int.from_bytes(data[:self.w8], byteorder='little')
        B = int.from_bytes(data[self.w8:], byteorder='little')
        for i in range(self.X, 0, -1):
            B = self.__rshift(B - self.M[2 * i + 1], A) ^ A
            A = self.__rshift(A - self.M[2 * i], B) ^ B
        B = (B - self.M[1]) % self.mod
        A = (A - self.M[0]) % self.mod
        return (A.to_bytes(self.w8, byteorder='little')
                + B.to_bytes(self.w8, byteorder='little'))

    def decryptFile(self, inputFileName, outputFileName):  # имя входного и выходного файлов
        with open(inputFileName, 'rb') as inp, open(outputFileName, 'wb') as out:
            run = True
            while run:
                text = inp.read(self.w4)
                if not text:
                    break
                if len(text) != self.w4:
                    run = False
                text = self.decryptBlock(text)
                if not run:
                    text = text.rstrip(b'\x00')  # удаляем добавленные на этапе шифрования байты
                out.write(text)

    def decryptBytes(self, data):
        res, run = b'', True
        while run:
            temp = data[:self.w4]
            if len(temp) != self.w4:
                run = False
            res += self.decryptBlock(temp)
            data = data[self.w4:]
            if not data:
                break
        return res.rstrip(b'\x00')