from RC5 import RC5

key = bytes(input("Ключ: "), 'utf-8')
w = int(input("Подблок: "))
X = int(input("Раунд: "))
text = bytes(input("Текст для шифрования: "), 'utf-8')

encrypt_text = RC5(w, X, key)
decrypt_text = RC5(w, X, key)

print("Шифр:", encrypt_text.encryptPart(text))

print("Первоначальный текст: " + (decrypt_text.decryptBlock(decrypt_text.encryptPart(text))).decode('utf-8'))