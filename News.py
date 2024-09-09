import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import bz2
import os
import threading

# Создаем окно приложения
root = tk.Tk()
root.title("Программа шифрования файлов")
root.geometry("400x300")  # Устанавливаем размер окна

# Глобальные переменные для хранения ключа и расширения файла
key = None
original_extension = None

# Функция для шифрования данных в отдельном потоке
def encrypt_data(cipher, data, output_file):
    compressed_data = bz2.compress(data)  # Сжимаем данные
    ciphertext, tag = cipher.encrypt_and_digest(compressed_data)

    with open(output_file, 'wb') as encrypted_file:
        encrypted_file.write(cipher.nonce)
        encrypted_file.write(tag)
        encrypted_file.write(ciphertext)

# Функция для выбора файла и шифрования
def encrypt_file():
    global key, original_extension
    file_path = filedialog.askopenfilename()
    if not file_path:  # Проверяем, был ли выбран файл
        messagebox.showwarning("Предупреждение", "Файл не выбран. Пожалуйста, выберите файл для шифрования.")
        return

    key = get_random_bytes(16)  # Генерируем случайный ключ длиной 16 байт
    cipher = AES.new(key, AES.MODE_EAX)  # Создаем объект шифра AES

    # Сохраняем исходное расширение файла
    _, original_extension = os.path.splitext(file_path)

    with open(file_path, 'rb') as file:
        data = file.read()

    # Создаем отдельный поток для шифрования данных
    output_file = file_path + ".enc"
    encrypt_thread = threading.Thread(target=encrypt_data, args=(cipher, data, output_file))
    encrypt_thread.start()

    # Дожидаемся завершения фонового потока перед выводом сообщения
    encrypt_thread.join()

    os.remove(file_path)  # Удаляем исходный файл

    messagebox.showinfo("Успех", f"Файл успешно зашифрован и сохранен как {output_file}")
    

# Функция для выбора зашифрованного файла и расшифровки
def decrypt_file():
    global key, original_extension
    if key is None:
        messagebox.showwarning("Предупреждение", "Ключ для расшифровки не найден. Пожалуйства, сначала выберите и зашифруйте файл.")
        return

    file_path = filedialog.askopenfilename()
    with open(file_path, 'rb') as file:
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    decompressed_data = bz2.decompress(data)  # Распаковываем данные

    # Восстанавливаем исходное расширение файла
    decrypted_file_path = file_path.replace(".enc", "") + original_extension
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decompressed_data)
    messagebox.showinfo("Успех.", "Файл успешно расшифрован и сохранен как  {decrypted_file_path}")

# Кнопка для выбора файла и шифрования
encrypt_button = tk.Button(root, text="Выбрать файл и зашифровать", command=encrypt_file, bg="blue", fg="white", font=("Helvetica", 12))
encrypt_button.pack(pady=20)

# Кнопка для выбора зашифрованного файла и расшифровки
decrypt_button = tk.Button(root, text="Выбрать зашифрованный файл и расшифровать", command=decrypt_file, bg="green", fg="white", font=("Helvetica", 12))
decrypt_button.pack(pady=10)

# Запуск основного цикла окна
root.mainloop()
