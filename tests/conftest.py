import pytest
import sys
import os
import tempfile

# Добавляем корень проекта в путь, чтобы импортировать app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app as flask_app, init_db, get_db


@pytest.fixture
def client():
    """
    Создаёт тестовый клиент Flask с временной БД.
    После теста БД удаляется.
    """
    # Создаём временный файл для БД
    db_fd, db_path = tempfile.mkstemp()

    # Подменяем имя БД в app
    flask_app.config['TESTING'] = True
    flask_app.config['DATABASE'] = db_path

    # Меняем рабочую директорию на temp для users.db
    original_cwd = os.getcwd()
    temp_dir = tempfile.mkdtemp()
    os.chdir(temp_dir)

    # Инициализируем тестовую БД
    init_db()

    # Отдаём клиент тестам
    with flask_app.test_client() as test_client:
        yield test_client

    # Уборка: возвращаем cwd, удаляем БД
    os.chdir(original_cwd)
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def db():
    """Прямой доступ к тестовой БД."""
    return get_db()


@pytest.fixture
def registered_user(client):
    """
    Фикстура: регистрирует пользователя и возвращает его данные.
    Пароль = 'Test1234!Pass' (валидный по zxcvbn).
    """
    username = 'testuser'
    salt = 'a' * 32                       # 32 символа
    password_hash = 'b' * 64              # 64 символа

    response = client.post('/api/register', json={
        'username': username,
        'passwordHash': password_hash,
        'salt': salt
    })

    assert response.status_code == 201, "Не удалось создать тестового пользователя"

    return {
        'username': username,
        'passwordHash': password_hash,
        'salt': salt
    }