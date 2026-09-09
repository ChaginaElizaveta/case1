from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import secrets

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
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Тестовый пользователь: test_user / test123
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            'test123'.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        
        cursor.execute('''
            INSERT INTO users (username, password_hash, salt)
            VALUES (?, ?, ?)
        ''', ('test_user', password_hash, salt))
        print('✅ Создан тестовый пользователь: test_user / test123')
    
    conn.commit()
    conn.close()
    print('✅ База данных готова')

# ============================================
# МАРШРУТЫ
# ============================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/get-salt', methods=['GET'])
def get_salt():
    username = request.args.get('username')
    
    if not username:
        return jsonify({'success': False, 'message': 'Имя пользователя обязательно'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'success': False, 'message': 'Пользователь не найден'}), 404
    
    return jsonify({'success': True, 'salt': user['salt']})

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password_hash = data.get('passwordHash')
    salt = data.get('salt')
    
    if not username or not password_hash or not salt:
        return jsonify({'success': False, 'message': 'Все поля обязательны'}), 400
    
    if len(username) < 3:
        return jsonify({'success': False, 'message': 'Логин минимум 3 символа'}), 400
    
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

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password_hash = data.get('passwordHash')
    
    if not username or not password_hash:
        return jsonify({'success': False, 'message': 'Все поля обязательны'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, username, password_hash 
        FROM users 
        WHERE username = ?
    ''', (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return jsonify({'success': False, 'message': 'Неверный логин или пароль'}), 401
    
    if user['password_hash'] == password_hash:
        return jsonify({
            'success': True,
            'message': 'Вход выполнен!',
            'user': {'id': user['id'], 'username': user['username']}
        })
    else:
        return jsonify({'success': False, 'message': 'Неверный логин или пароль'}), 401

# ============================================
# ЗАПУСК
# ============================================

if __name__ == '__main__':
    print('\n' + '='*60)
    print('🚀 ЗАПУСК СЕРВЕРА')
    print('='*60)
    init_db()
    print('\n📝 Тестовый пользователь: test_user / test123')
    print('🌐 Откройте: http://localhost:5000')
    print('='*60 + '\n')
    app.run(debug=True, port=5000)