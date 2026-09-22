"""
Основной файл приложения «Расписание учебной группы» (Этапы 3–4 ТЗ).

Маршруты:
    GET/POST /register  — регистрация пользователя
    GET/POST /login     — авторизация
    GET      /logout    — выход из системы
    GET      /schedule  — расписание группы текущего пользователя
                           (защищён декоратором login_required)

Запуск:
    python app.py
"""

import os
import sqlite3
from functools import wraps

from flask import (
    Flask, flash, g, redirect, render_template, request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "schedule.db")

# Порядок дней недели для группировки расписания
WEEKDAYS_ORDER = [
    "Понедельник", "Вторник", "Среда", "Четверг", "Пятница",
    "Суббота", "Воскресенье",
]

app = Flask(__name__)
# Ключ для подписи сессий (для локальной разработки)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")


# ------------------------- Работа с БД -------------------------

def get_db():
    """Подключение к БД на время одного запроса (хранится в flask.g)."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Закрывает подключение к БД по завершении запроса."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ----------------- Декоратор защиты доступа (4.4 ТЗ) -----------------

def login_required(view):
    """Если в сессии нет user_id — перенаправляет на страницу /login."""
    @wraps(view)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Для просмотра расписания нужно войти в систему.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return decorated_function


# --------------------------- Маршруты ---------------------------

@app.route("/")
def index():
    """Главная страница — перенаправление на расписание (оно защищено)."""
    return redirect(url_for("schedule"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Регистрация: логин, пароль (хешируется) и название группы (4.3 ТЗ)."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        group_name = request.form.get("group_name", "").strip()

        if not username or not password or not group_name:
            flash("Заполните все поля формы.", "error")
        else:
            db = get_db()
            exists = db.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            ).fetchone()
            if exists:
                flash("Пользователь с таким логином уже существует.", "error")
            else:
                # Пароль в БД сохраняется только в виде хеша (4.1 ТЗ)
                password_hash = generate_password_hash(password)
                db.execute(
                    "INSERT INTO users (username, password_hash, group_name) "
                    "VALUES (?, ?, ?)",
                    (username, password_hash, group_name),
                )
                db.commit()
                flash("Регистрация прошла успешно! Теперь войдите в систему.",
                      "success")
                return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Авторизация: проверка пользователя и пароля через check_password_hash."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash, group_name FROM users "
            "WHERE username = ?",
            (username,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"],
                                                   password):
            flash("Неверный логин или пароль.", "error")
        else:
            # В сессию записываются user_id и group_name (4.2 ТЗ)
            session["user_id"] = user["id"]
            session["group_name"] = user["group_name"]
            flash(f"Добро пожаловать, {user['username']}!", "success")
            return redirect(url_for("schedule"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Выход из системы: сессия очищается, переход на /login (4.3 ТЗ)."""
    session.clear()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("login"))


@app.route("/schedule")
@login_required
def schedule():
    """Расписание: только занятия группы, сохранённой в сессии (5.1 ТЗ)."""
    group_name = session["group_name"]
    db = get_db()
    rows = db.execute(
        "SELECT weekday, lesson_number, time_start, time_end, subject, "
        "       teacher, room "
        "FROM schedule WHERE group_name = ? ORDER BY lesson_number, id",
        (group_name,),
    ).fetchall()

    by_day = {}
    for row in rows:
        by_day.setdefault(row["weekday"], []).append(row)

    # Группировка по дням недели в корректном порядке
    grouped = [(day, by_day[day]) for day in WEEKDAYS_ORDER if day in by_day]

    return render_template("schedule.html", group_name=group_name,
                           grouped=grouped)


if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        # Автоматически создаём и заполняем БД при первом запуске
        import database
        database.init_db()
        database.fill_test_data()
    app.run(debug=True, use_reloader=False)
