import sqlite3

# Подключение к базе данных SQLite
conn = sqlite3.connect('encryption_keys.db')
cur = conn.cursor()

# Создание таблицы для хранения ключей шифрования
cur.execute('''
    CREATE TABLE IF NOT EXISTS encryption_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            encryption_key BLOB NOT NULL
            )
''')

# Завершение транзакции и закрытие содениения
conn.commit()
conn.close()