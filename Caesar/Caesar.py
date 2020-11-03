alphabet = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz"
encrypt = input("Введите сообщение для шифрования: ")
key = int(input("Введите ключ: "))
encrypt = encrypt.lower()
encrypted = ""

# Шифрование
for i in encrypt:
    position = alphabet.find(i)  # возвращает порядковый номер
    newPosition = position + key  # к индексу буквы прибавляет ключ
    if i in alphabet:
        encrypted += alphabet[newPosition]
    else:
        encrypted += i
print("Шифр: " + encrypted)

# Дешифрование
decrypt = encrypted
decrypted = ""
for i in decrypt:
    dPosition = alphabet.find(i)
    dNewPosition = dPosition - key
    if i in alphabet:
        decrypted += alphabet[dNewPosition]
    else:
        decrypted += i
print("Исходное сообщение: " + decrypted)

