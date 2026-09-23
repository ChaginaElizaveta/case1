"""
Тесты для системы аутентификации.

Покрываемые сценарии:
1. Запрос challenge без username
2. Запрос challenge для существующего пользователя
3. Challenge уникален (два запроса → разные)
4. Вход без challenge
5. Вход без timestamp
6. Вход с просроченным timestamp (>5 мин)
7. Повторное использование challenge
"""

import time


# ============================================
# ТЕСТ 1: Запрос challenge без username
# ============================================

def test_get_challenge_without_username(client):
    """
    GET /api/get-challenge без параметра username.
    Ожидаем: 400, success = False, сообщение об ошибке.
    """
    response = client.get('/api/get-challenge')

    assert response.status_code == 400
    data = response.get_json()
    assert data['success'] is False
    assert 'обязательно' in data['message'].lower()


# ============================================
# ТЕСТ 2: Запрос challenge для существующего пользователя
# ============================================

def test_get_challenge_for_existing_user(client, registered_user):
    """
    GET /api/get-challenge?username=testuser.
    Ожидаем: 200, есть salt, challenge, timestamp, expiresIn.
    """
    response = client.get(f"/api/get-challenge?username={registered_user['username']}")

    assert response.status_code == 200
    data = response.get_json()

    assert data['success'] is True
    assert 'salt' in data
    assert 'challenge' in data
    assert 'timestamp' in data
    assert 'expiresIn' in data

    # Проверяем значения
    assert data['salt'] == registered_user['salt']
    assert len(data['challenge']) == 64   # 32 байта = 64 hex-символа
    assert data['expiresIn'] == 300
    assert isinstance(data['timestamp'], int)
    # Timestamp должен быть примерно "сейчас"
    assert abs(data['timestamp'] - int(time.time())) < 5


# ============================================
# ТЕСТ 3: Challenge уникален (два запроса → разные)
# ============================================

def test_challenge_is_unique(client, registered_user):
    """
    Два запроса challenge → два РАЗНЫХ challenge.
    Ожидаем: разные строки, обе сохранены в БД.
    """
    username = registered_user['username']

    # Первый запрос
    r1 = client.get(f"/api/get-challenge?username={username}")
    challenge_1 = r1.get_json()['challenge']

    # Второй запрос
    r2 = client.get(f"/api/get-challenge?username={username}")
    challenge_2 = r2.get_json()['challenge']

    # Проверки
    assert challenge_1 != challenge_2
    assert len(challenge_1) == 64
    assert len(challenge_2) == 64


# ============================================
# ТЕСТ 4: Вход без challenge
# ============================================

def test_login_without_challenge(client, registered_user):
    """
    POST /api/login без поля challenge.
    Ожидаем: 400, success = False.
    """
    response = client.post('/api/login', json={
        'username': registered_user['username'],
        'passwordHash': registered_user['passwordHash'],
        'timestamp': int(time.time())
        # challenge отсутствует
    })

    assert response.status_code == 400
    data = response.get_json()
    assert data['success'] is False
    assert 'обязательны' in data['message'].lower()


# ============================================
# ТЕСТ 5: Вход без timestamp
# ============================================

def test_login_without_timestamp(client, registered_user):
    """
    POST /api/login без поля timestamp.
    Ожидаем: 400, success = False.
    """
    response = client.post('/api/login', json={
        'username': registered_user['username'],
        'passwordHash': registered_user['passwordHash'],
        'challenge': 'x' * 64
        # timestamp отсутствует
    })

    assert response.status_code == 400
    data = response.get_json()
    assert data['success'] is False
    assert 'обязательны' in data['message'].lower()


# ============================================
# ТЕСТ 6: Вход с просроченным timestamp (>5 мин)
# ============================================

def test_login_with_expired_timestamp(client, registered_user):
    """
    POST /api/login с timestamp, которому больше 5 минут.
    Ожидаем: 401, success = False, сообщение "устарел".
    """
    # Получаем валидный challenge
    r = client.get(f"/api/get-challenge?username={registered_user['username']}")
    challenge_data = r.get_json()

    # Подделываем timestamp: 10 минут назад
    expired_timestamp = int(time.time()) - 600  # 600 сек = 10 минут

    response = client.post('/api/login', json={
        'username': registered_user['username'],
        'passwordHash': registered_user['passwordHash'],
        'challenge': challenge_data['challenge'],
        'timestamp': expired_timestamp
    })

    assert response.status_code == 401
    data = response.get_json()
    assert data['success'] is False
    assert 'устарел' in data['message'].lower()


# ============================================
# ТЕСТ 7: Повторное использование challenge
# ============================================

def test_challenge_reuse_rejected(client, registered_user):
    """
    Первый вход с challenge успешен (даже с неправильным паролем,
    так как цель — проверить, что challenge помечен использованным).
    Второй вход с ТЕМ ЖЕ challenge → отказ.

    Проверяем именно защиту от Replay Attack.
    """
    username = registered_user['username']

    # Получаем challenge
    r = client.get(f"/api/get-challenge?username={username}")
    challenge_data = r.get_json()

    challenge = challenge_data['challenge']
    timestamp = challenge_data['timestamp']

    # Первый вход (правильный хеш)
    response_1 = client.post('/api/login', json={
        'username': username,
        'passwordHash': registered_user['passwordHash'],
        'challenge': challenge,
        'timestamp': timestamp
    })

    # Первый вход должен пройти успешно
    assert response_1.status_code == 200
    assert response_1.get_json()['success'] is True

    # Второй вход с ТЕМ ЖЕ challenge (Replay Attack)
    response_2 = client.post('/api/login', json={
        'username': username,
        'passwordHash': registered_user['passwordHash'],
        'challenge': challenge,  # тот же!
        'timestamp': timestamp    # тот же!
    })

    # Должен быть отказ
    assert response_2.status_code == 401
    data_2 = response_2.get_json()
    assert data_2['success'] is False
    assert 'использован' in data_2['message'].lower()