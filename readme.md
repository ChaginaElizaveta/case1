# 🔐 Система аутентификации

Регистрация и вход с хешированием пароля на клиенте.
---

## 🛠️ Технологии

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, Flask
- **БД:** SQLite
- **Хеширование:** PBKDF2 (Web Crypto API)
- **Проверка пароля:** zxcvbn (JS)

---

## 📁 Структура

```
case1/
├── app.py
├── requirements.txt
├── templates/
│   └── index.html
├── users.db
└── venv/
```

---

## 🚀 Запуск

```bash
.\venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Открыть: http://localhost:5000

---

## 🔄 Как работает

### Регистрация

**Клиент:**
1. Ввод логина и пароля
2. zxcvbn проверяет силу (оценка ≥ 3)
3. Генерация соли (16 байт)
4. PBKDF2(password + salt) — 100 000 итераций
5. Отправка `{username, passwordHash, salt}`

**Сервер:**
1. Проверка уникальности логина
2. Сохранение в таблицу `users`

### Вход

**Клиент:**
1. Запрос `challenge + salt + timestamp`
2. PBKDF2(password + salt)
3. Отправка `{username, passwordHash, challenge, timestamp}`

**Сервер:**
1. Проверка timestamp (< 5 минут)
2. Проверка challenge (существует, не использован)
3. Пометка challenge использованным
4. Сравнение хешей через `secrets.compare_digest`

### SHA256:
    Входные данные 
    --> Добавление паддинга 
    --> Разбивка на блоки по 512 бит 
    --> Инициализация 8 констант 
    --> Для каждого блока 
    --> 64 раунда преобразований 
    --> Сложение с предыдущим хешем 
    --> Финальный хеш 256 бит
    
## 🗄️ База данных

### `users` 
- `id` — первичный ключ
- `username` — логин (уникальный)
- `password_hash` — PBKDF2-хеш (64 hex)
- `salt` — соль (32 hex)
- `created_at` — дата регистрации

### `challenges`
- `id` — первичный ключ
- `username` — кому выдан
- `challenge` — случайная строка (64 hex)
- `created_at` — когда создан
- `used` — 0/1

---

## 🔒 Защита

| Механизм | От чего |
|----------|---------|
| PBKDF2 + соль | Взлом при утечке БД |
| Хеш на клиенте | Перехват пароля |
| Challenge | Replay Attack |
| Timestamp 5 мин | Старые запросы |
| zxcvbn | Слабые пароли |

