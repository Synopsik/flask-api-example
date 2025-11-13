from flask import Flask, render_template, g
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms.fields.simple import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Regexp, DataRequired
import sqlite3
from sqlite3 import Connection

app = Flask(__name__)
app.config['SECRET_KEY'] = 'StevenBaarCIS256'
bcrypt = Bcrypt(app)

DATABASE = 'students.db'

# --------------------------------------------------------------------------------------- #
#                                        Flask WTForms                                    #
# --------------------------------------------------------------------------------------- #
class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[
            InputRequired('Username required!'),
            Length(min=2, max=25, message='Username must be between 2 to 25 characters'),
            Regexp(
                r"^[A-Za-z0-9_]+$",
                message="Username can only contain letters, numbers, and underscores.",
            ),
        ],
    )

    password = PasswordField(
        'Password',
        validators=[
            DataRequired(message="Password is required."),
            Length(min=8, message="Password must be at least 8 characters."),
            Regexp(
                r"^(?=.*[A-Za-z])(?=.*\d).+$",
                message="Password must contain both letters and numbers.",
            ),
        ],
    )

    submit = SubmitField("Login")

# --------------------------------------------------------------------------------------- #
#                                          Flask                                          #
# --------------------------------------------------------------------------------------- #
@app.route("/")
@app.route("/index", methods=['GET'])
def index():
    return render_template('index.html', title='Home')


@app.route("/login", methods=['GET'])
def login_form():
    form = LoginForm()
    return render_template('login_form.html', title='Login', form=form)


@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()

    if not form.validate_on_submit():
        errors = form.errors
        return render_template('login_form.html', title='Login', form=form, errors=errors)

    username = form.username.data
    entered_password = form.password.data

    conn = get_db()
    cursor = conn.execute("SELECT password FROM students WHERE username = ?",
                          (username,))
    result = cursor.fetchone()

    if result is None:
        return "User not found!"

    stored_password = result[0]

    if not bcrypt.check_password_hash(stored_password, entered_password):
        return "Incorrect log in!"

    return "Successfully logged in"


@app.route('/register', methods=['GET'])
def register_form():
    form = LoginForm()
    return render_template('register_form.html', title='Register', form=form)


@app.route('/register', methods=['POST'])
def register():
    form = LoginForm()

    if not form.validate_on_submit():
        errors = form.errors
        return render_template('register_form.html', title='Register', form=form, errors=errors)

    username = form.username.data
    password = form.password.data
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_db()
    conn.execute(
        "INSERT INTO students (username, password) VALUES (?, ?)",
        (username, hashed_password)
    )

    conn.commit()

    return f'{username} Added!'


@app.route("/students", methods=['GET'])
def employees():
    mytitle = "User Database Records"
    formatted_students = []

    conn = get_db()
    cursor = conn.execute('SELECT * FROM students')
    all_students = cursor.fetchall()

    # Fetch returns a tuple (ID, USERNAME, PASSWORD)
    print(all_students)

    for student in all_students:
        formatted_students.append(
            # Must be formatted as a list of dicts
            {"username":student[1], "password":student[2]}
        )

    print(formatted_students)
    # [{ username: "username", password: "password" }, ...]
    return render_template('dataexamples.html', title=mytitle, data=formatted_students)


@app.route("/init_db")
def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.commit()
    return "Database and 'students' table initialized."

# --------------------------------------------------------------------------------------- #
#                                    DB Connections                                       #
# --------------------------------------------------------------------------------------- #
def get_db() -> Connection:
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception) -> None:
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --------------------------------------------------------------------------------------- #
#                                        Startup                                          #
# --------------------------------------------------------------------------------------- #
if __name__ == "__main__":
    app.run()