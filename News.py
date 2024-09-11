import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import bz2
import os
import shutil
import pyzipper
import sqlite3
from functools import partial

# Создаем окно приложения
root = tk.Tk()
root.title("Программа шифрования файлов")
root.geometry("500x500") # Устанавливаем размер окна

# Глобальная переменная для хранения ключа и расширения файла
key = None
original_extension = None

# Создание базы данных и таблицы для хранения ключей шифрования
def create_encryption_keys_table():
    conn = sqlite3.connect('encryption_keys.db')
    cur = conn.cursor()
    cur.execute(''' CREATE TABLE IF NOT EXISTS encryption_keys (
                file_path TEXT PRIMARY KEY,
                encryption_key BLOB
                )''')
    conn.commit()
    conn.close()

# Добавление ключа шифрования в базу данных с обновлением, если file_path уже существует
def add_encryption_key(file_path, encryption_key):
    conn = sqlite3.connect('encryption_keys.db')
    cur = conn.cursor()
    try:
        cur.execute('INSERT OR REPLACE INTO encryption_keys (file_path, encryption_key) VALUES (?, ?)', (file_path, encryption_key))
        conn.commit()
        print(f"Ключ успешно добавлен в базу данных для файла: {file_path}")
    except sqlite3.Error as e:
        print(f"Ошибка при добавлении ключа в базу данных: {e}")
    finally:
        conn.close()
    
# Получение ключа шифрования из базы данных
def get_encryption_key(file_path):
    conn = sqlite3.connect('encryption_keys.db')
    cur = conn.cursor()
    cur.execute('SELECT encryption_key FROM encryption_keys WHERE file_path = ?', (file_path,))
    result = cur.fetchone()
    conn.close()
    return result[0] if result else None

# Обновление ключа шифрования в базу данных
def update_encryption_key(file_path, new_encryption_key):
    conn = sqlite3.connect('encryption_keys.db')
    cur = conn.cursor()
    cur.execute('UPDATE encryption_keys SET encryption_key = ? WHERE file_path = ?', (new_encryption_key, file_path))
    conn.commit()
    conn.close()

# Создание таблицы перед использованием других функций
create_encryption_keys_table()

# Модифицированная функция для шифрования данных с передачей ключа
def encrypt_data(cipher, key, data, output_file):
    compressed_data = bz2.compress(data) # Сжимаем данные
    ciphertext, tag = cipher.encrypt_and_digest(compressed_data)

    with open(output_file, 'wb') as encrypt_file:
        encrypt_file.write(cipher.nonce)
        encrypt_file.write(tag)
        encrypt_file.write(ciphertext)

# Фунция для выбора файла и шифрования с сохранением ключей в базе данных
def encrypt_file():
    global key, original_extension
    file_path = filedialog.askopenfilename()
    if not file_path: # Проверяем, был ли выбран файл
        messagebox.showwarning("Предупреждение", "Файл не выбран. Пожалуйста, выберите файл для шифрования.")
        return
    
    # Сохраняем исходное расширение файла
    original_extension = os.path.splitext(file_path)[1] if file_path else ""

    key = get_random_bytes(16) # Генерируем случайный ключ длиной 16 байт
    cipher = AES.new(key, AES.MODE_EAX) # Создаем объект шифра AES

    with open(file_path, 'rb') as file:
        data = file.read()

    compressed_data = bz2.compress(data) # Сжимаем данные

    # Убираем текущее расширение файла и добавляем расширение .enc
    encrypted_file_path = file_path.rsplit(".", 1)[0] + ".enc"

    ciphertext, tag = cipher.encrypt_and_digest(compressed_data)

    # Записываем зашифрованные данные в новый файл
    with open(encrypted_file_path, 'wb') as encrypt_file:
        encrypt_file.write(cipher.nonce)
        encrypt_file.write(tag)
        encrypt_file.write(ciphertext)

    # Удаляем оригинальный файл
    os. remove(file_path)

    # Сохраняем ключ шифрования в базе данных
    add_encryption_key(encrypted_file_path, key)

    messagebox.showinfo("Успех", f"Файл успешно зашифрован и сохранен как {encrypted_file_path}")


# Функция для удаления ключа шифрования из базы данных
def delete_encryption_key(file_path):
    conn = sqlite3.connect('encryption_keys.db')
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM encryption_keys WHERE file_path = ?', (file_path,))
        conn.commit()
        print(f"Ключ успешно удален из базы данных для файла: {file_path}")
    except sqlite3.Error as e:
        print(f"Ошибка при удалении ключа из базы данных: {e}")
    finally:
        conn.close()

# Функция для выбора зашифрованного файла для расшифровки с использованием ключа из базы данных
def decrypt_file():
    global key, original_extension
    decrypted_file_path = "" # Инициализируем переменную здесь

    file_path = filedialog.askopenfilename()
    if not file_path: # Проверяем, был ли выбран файл
        messagebox.showwarning("Предупреждение", "Файл не выбран. Пожалуйста, выберите зашифрованный файл для расшифровки.")
        return
    
    # Получаем ключ шифрования из базы данных
    key = get_encryption_key(file_path)
    if key is None:
        messagebox.showwarning("Предупреждение", "Ключ для расшифровки не найден. Пожалуйста, выберите зашифрованный файл.")
        return

    with open(file_path, 'rb') as file:
        nonce = file.read(16)
        tag = file.read(16)
        ciphertext = file.read()

    cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    decompressed_data = bz2.decompress(data) # Раскапоквываем данные

    # Восстанавливаем исходное расширение файла
    if original_extension is not None:
        decrypted_file_path = file_path.replace(".enc", "") + original_extension
    else:
        decrypted_file_path = file_path.replace(".enc", "")

    # Проверяем, нужно ли добавить исходное расширение к пути расшифрованного файла
    if not decrypted_file_path.endswith(original_extension):
        decrypted_file_path += original_extension

    # Открываем файл для записи бинарных данных и записываем расшифрованные данные
    if decrypted_file_path:
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decompressed_data)
        messagebox.showinfo("Успех", f"Файл успешно расшифрован и сохранен как {decrypted_file_path}")
    else:
        messagebox.showerror("Ошибка", "Некорректный путь к файлу для записи.")

    # Удаляем дублирующееся расширения, если оно уже присутствует
    if decrypted_file_path.endswith(".pdf.pdf"):
        decrypted_file_path = decrypted_file_path[:-4]

    # Проверяем, нужно ли добавить исходное расширение к пути расшифрованного файла
    if original_extension is not None and not decrypted_file_path.endswith(original_extension):
        decrypted_file_path += original_extension

    # Открываем файл для записи бинарных данных и записываем расшифрованные данные
    if decrypted_file_path:
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decompressed_data)
        messagebox.showinfo("Успех", f"Файл успешно расшифрован и сохранен как {decrypted_file_path}")

        # Удаляем файл с расширением .enc после успешной расшифровки
        os.remove(file_path)

    else:
        messagebox.showerror("Ошибка", "Некорректный путь к файлу для записи.")

# Функция для шифрования папки, удаления оригинальных файлов и создания архива с паролем
def encrypt_folder():
    global key
    folder_path = filedialog.askdirectory()  # Выбор папки для шифрования
    if not folder_path:
        messagebox.showwarning("Предупреждение", "Папка не выбрана. Пожалуйста, выберите папку для шифрования.")
        return

    key = get_random_bytes(16)  # Генерируем случайный ключ длиной 16 байт

    zip_file_name = os.path.basename(folder_path) + "_encrypted.zip"  # Имя архива

    with pyzipper.AESZipFile(zip_file_name, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zip_file:
        zip_file.setpassword(b'V#j*&xicjSz8s4*1')

        for root, _, files in os.walk(folder_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                with open(file_path, 'rb') as file:
                    data = file.read()

                compressed_data = bz2.compress(data)

                # Убираем текущее расширение файла и добавляем расширение .enc
                encrypted_file_path = file_path.rsplit(".", 1)[0] + ".enc"

                # Записываем зашифрованные данные в архив
                zip_file.writestr(os.path.relpath(encrypted_file_path, folder_path), compressed_data)

                # Удаляем оригинальный файл
                os.remove(file_path)

    # Удаляем папку после создания архива
    shutil.rmtree(folder_path)

    messagebox.showinfo("Успех", f"Папка успешно зашифрована, оригинальные файлы удалены, и создан архив: {zip_file_name} с паролем.")

# Функция для обработки расшифровки архива и автоматической расшифровки файлов внутри архива
def on_decrypt_button_click(archive_path, password):
    try:
        with pyzipper.AESZipFile(archive_path, 'r') as zip_file:
            zip_file.setpassword(password.encode())

            # Создаем папку для извлеченных файлов
            extract_folder = os.path.splitext(archive_path)[0]
            os.makedirs(extract_folder, exist_ok = True)

            # Извлекаем файлы из архива
            zip_file.extractall(extract_folder)

            # Расшифровываем каждый файл внутри архива
            for root, _, files in os.walk(extract_folder):
                for file_name in files:
                    file_path = os.path.join(root, file_name) # Проверяем, что файл зашифрован
                    with open(file_path, 'rb') as file:
                        nonce = file.read(16)
                        tag = file.read(16)
                        ciphertext = file.read()

                    cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
                    data = cipher.decrypt_and_verify(ciphertext, tag)
                    
                    decompressed_data = bz2.decompress(data) # Распаковываем данные

                    # Восстанавливаем исходное расширение файла
                    decrypted_file_path = file_path.replace(".enc", "")

                    # Открываем файл для записи бинарных данных и записываем расшифрованные данные
                    with open(decrypted_file_path, 'wb') as decrypted_file:
                        decrypted_file.write(decompressed_data)

                    # Удаляем зашифрованный файл после успешной расшифровки
                    os.remove(file_path)
        
        # Удаляем зашифрованный архив после успешной расшифровки и извлечения файлов
        os.remove(archive_path)

        return f"Архив успешно расшифрован и файлы извлечены в папку: {extract_folder}"
    except pyzipper.BadPassword:
        return "Неверный пароль для расшифровки арихва"
    except Exception as e:
        return f"Произошла ошибка при расшифровке архива: {str(e)}" 

# Функция для вызова on_decrypt_button_click с аргументами
def call_decrypt(archive_path, password):
    return partial(on_decrypt_button_click, archive_path, password)

# Модифицированная функция для расшировки всех файлов в указанной папке
def decrypt_all_files_in_folder(folder_path):
    global key
    if key is None:
        messagebox.showwarning("Предупреждение", "Ключ для расшифровки не найден. Пожалуйства, выберите зашифрованный файл.")
        return
    
    for root, _, files in os.walk(folder_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.endswith(".enc"): # Проверяем, что файл зашифрован
                with open(file_path, 'rb') as file:
                    nonce = file.read(16)
                    tag = file.read(16)
                    ciphertext = file.read()
                
                cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
                try:
                    data = cipher.decrypt_and_verify(ciphertext, tag)
                except ValueError as e:
                    messagebox.showerror("Ошибка", f"Ошибка при расшифровке файла: {str(e)}")
                    continue

                decompressed_data = bz2.decompress(data) # Распаковываем данные

                # Восстанавливаем исходное расширение файла
                decrypted_file_path = file_path.replace(".enc", "")

                # Открываем файл для записи бинарных данных и записываем расшифрованные данные
                with open(decrypted_file_path, 'wb') as decrypted_file:
                    decrypted_file.write(decompressed_data)

                # Удаляем зашифрованный файл после успешной расшифровки
                os.remove(file_path)

                # Удаляем ключ из базы данных
                delete_encryption_key(file_path)
    
    messagebox.showinfo("Успех", "Все файлы в папке успешно расшифрованы и ключи удалены из базы данных.")

# Функция для обработки события нажатия на кнопку
def on_decrypt_folder_button_click():
    folder_path = filedialog.askdirectory() # Выбор папки для расшифровки файлов
    
    if not folder_path:
        messagebox.showwarning("Предупреждение", "Папка не выбрана. Пожалуйста, выберите папку для расшифровки файлов.")
        return
    
    decrypt_all_files_in_folder(folder_path) # Вызов функции для расшифровки всех файлов в папке
    messagebox.showinfo("Успех", "Все файлы в папке успешно расшифрованы.")


# Функция для добавления данных в таблицу с выводом сообщения
def add_encryption_key(file_path, encryption_key):
    conn = sqlite3.connect('encryption_keys.db')
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO encryption_keys (file_path, encryption_key) VALUES (?, ?)', (file_path, encryption_key))
        conn.commit()
        print(f"Ключ успешно добавлен в базу данных для файла: {file_path}")
    except sqlite3.Error as e:
        print(f"Ошибка при добавлении ключа в базу данных: {e}")
    finally:
        conn.close()

# Функция для извлечения данных из таблицы
def get_encryption_key(file_path):
    conn = sqlite3.connect('encryption_keys.db')
    cur = conn.cursor()
    cur.execute('SELECT encryption_key FROM encryption_keys WHERE file_path = ?', (file_path,))
    result = cur.fetchone()
    conn.close()
    return result[0] if result else None

# Функция для обновления данных в таблице
def update_encryption_key(file_path, new_encryption_key):
    conn = sqlite3.connect('encryption_keys.db')
    cur = conn.cursor()
    cur.execute('UPDATE encryption_keys SET encryption_key = ? WHERE file_path = ?', (new_encryption_key, file_path))
    conn.commit()
    conn.close()

# Кнопка для выбора файла для шифрования
encrypt_button = tk.Button(root, text = "Шифровать файл", command = encrypt_file, bg="blue", fg="white", font=("Helvetica", 12))
encrypt_button.pack(pady = 10)

# Кнопка для выбора папки для шифрования
encrypt_folder_button = tk.Button(root, text = "Шифровать папку", command = encrypt_folder, bg="blue", fg="white", font=("Helvetica", 12))
encrypt_folder_button.pack(pady = 20)

# Кнопка для выбора файла для расшифровки
decrypt_button = tk.Button(root, text = "Расшифровать файл", command = decrypt_file, bg="green", fg="white", font=("Helvetica", 12))
decrypt_button.pack(pady = 10)

# Кнопка для выбора архива для расшифровки
decrypt_folder_button = tk.Button(root, text="Расшифровать архив", command=on_decrypt_button_click, bg="green", fg="white", font=("Helvetica", 12))
decrypt_folder_button.pack(pady = 20)

# Кнопка для выбора папки для расшифровки файлов в ней
decrypt_folder_files_button = tk.Button(root, text = "Расшифровать файлы в папке", command = on_decrypt_folder_button_click, bg="green", fg="white", font=("Helvetica", 12))
decrypt_folder_files_button.pack(pady = 20)


# Запуск основного цикла окна
root.mainloop()