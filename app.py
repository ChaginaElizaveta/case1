from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import sqlite3
import secrets
import time

app = Flask(__name__)
CORS(app)

# ============================================
# БАЗА ДАННЫХ
# ============================================

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Таблица пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Таблица для защиты от Replay Attack
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            challenge TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used INTEGER DEFAULT 0
        )
    ''')

    conn.commit()
    conn.close()
    print('✅ База данных инициализирована')

def cleanup_old_challenges():
    """Удаляет challenges старше 5 минут"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        DELETE FROM challenges
        WHERE created_at < datetime('now', '-2 minutes')
    ''')
    conn.commit()
    conn.close()

# ============================================
# МАРШРУТЫ
# ============================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    """
    Регистрация нового пользователя.
    Принимает: username, passwordHash, salt.
    Пароль открытым текстом НЕ принимается.
    """
    data = request.json
    username = data.get('username')
    password_hash = data.get('passwordHash')
    salt = data.get('salt')

    if not username or not password_hash or not salt:
        return jsonify({'success': False, 'message': 'Все поля обязательны'}), 400

    if len(username) < 3:
        return jsonify({'success': False, 'message': 'Логин минимум 3 символа'}), 400

    if len(password_hash) != 64 or len(salt) != 32:
        return jsonify({'success': False, 'message': 'Некорректные данные'}), 400

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'Имя уже занято'}), 409

    cursor.execute('''
        INSERT INTO users (username, password_hash, salt)
        VALUES (?, ?, ?)
    ''', (username, password_hash, salt))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': 'Регистрация успешна!'}), 201

@app.route('/api/get-challenge', methods=['GET'])
def get_challenge():
    """Выдаёт challenge + salt + timestamp для входа"""
    username = request.args.get('username')

    if not username:
        return jsonify({'success': False, 'message': 'Имя пользователя обязательно'}), 400

    cleanup_old_challenges()

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({'success': False, 'message': 'Пользователь не найден'}), 404

    challenge = secrets.token_hex(32)
    cursor.execute('''
        INSERT INTO challenges (username, challenge)
        VALUES (?, ?)
    ''', (username, challenge))
    conn.commit()
    conn.close()

    timestamp = int(time.time())

    return jsonify({
        'success': True,
        'salt': user['salt'],
        'challenge': challenge,
        'timestamp': timestamp,
        'expiresIn': 120
    })

@app.route('/api/login', methods=['POST'])
def login():
    """Аутентификация пользователя"""
    data = request.json
    username = data.get('username')
    password_hash = data.get('passwordHash')
    challenge = data.get('challenge')
    timestamp = data.get('timestamp')

    if not all([username, password_hash, challenge, timestamp]):
        return jsonify({'success': False, 'message': 'Все поля обязательны'}), 400

    # Проверка timestamp
    current_time = int(time.time())
    if abs(current_time - int(timestamp)) > 120:
        return jsonify({'success': False, 'message': 'Запрос устарел'}), 401

    conn = get_db()
    cursor = conn.cursor()

    # Проверка challenge
    cursor.execute('''
        SELECT id, used FROM challenges
        WHERE challenge = ? AND username = ?
    ''', (challenge, username))

    challenge_row = cursor.fetchone()

    if not challenge_row:
        conn.close()
        return jsonify({'success': False, 'message': 'Недействительный challenge'}), 401

    if challenge_row['used']:
        conn.close()
        return jsonify({'success': False, 'message': 'Challenge уже использован!'}), 401

    cursor.execute('UPDATE challenges SET used = 1 WHERE id = ?', (challenge_row['id'],))

    cursor.execute('''
        SELECT id, username, password_hash
        FROM users
        WHERE username = ?
    ''', (username,))

    user = cursor.fetchone()
    conn.commit()
    conn.close()

    if not user:
        return jsonify({'success': False, 'message': 'Неверный логин или пароль'}), 401

    if secrets.compare_digest(user['password_hash'], password_hash):
        return jsonify({
            'success': True,
            'message': 'Вход выполнен успешно!',
            'user': {
                'id': user['id'],
                'username': user['username']
            }
        })
    else:
        return jsonify({'success': False, 'message': 'Неверный логин или пароль'}), 401

# ============================================
# ЗАПУСК
# ============================================

if __name__ == '__main__':
    print('\n' + '=' * 60)
    print('🚀 ЗАПУСК СЕРВЕРА')
    print('=' * 60)
    init_db()
    print('🌐 Откройте: http://localhost:5000')
    print('=' * 60 + '\n')
    app.run(debug=True, port=5000)