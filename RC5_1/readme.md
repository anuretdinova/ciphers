# Запуск шифрования:
# file.txt - файл с текстом для шифрования, key.txt - ключ шифрования
python encrypt.py -i file.txt -o encrypted.txt -k key.txt   

# Запуск дешифрования: 
# encrypted.txt - файл из предыдущего шага, key.txt - ключ шифрования
python decrypt.py -i encrypted.txt -o decrypted.txt -k key.txt 
