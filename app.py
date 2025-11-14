# Steven Baar
# CIS256 Fall 2025
# Programming Assignment 5 (PA 5)
from flask import Flask, render_template, g
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms.fields.simple import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Regexp, DataRequired
import sqlite3
from sqlite3 import Connection
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') # Better to use an env variable for keys and secrets
bcrypt = Bcrypt(app)

DATABASE = 'students.db' # Database name

# --------------------------------------------------------------------------------------- #
#                                        Flask WTForms                                    #
# --------------------------------------------------------------------------------------- #
class LoginForm(FlaskForm):
    """
    Represents the login form for user authentication.

    This form includes fields for entering a username and password, as well
    as submit buttons for login and registration. It applies validation rules
    to ensure input correctness and security. Typical usage involves rendering
    this form in a login page for processing user credentials.

    :ivar username: Field for the user to input their username. Requires input
         and validates that the username is 2-25 characters long and contains
         only letters, numbers, and underscores.
    :type username: StringField
    :ivar password: Field for the user to input their password. Requires input
         and validates that the password is at least 8 characters long,
         containing both letters and numbers.
    :type password: PasswordField
    :ivar submit: Button to submit the form for login.
    :type submit: SubmitField
    :ivar register: Button to submit the form to indicate a registration request.
    :type register: SubmitField
    """
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
    register = SubmitField("Register")

# --------------------------------------------------------------------------------------- #
#                                          Flask                                          #
# --------------------------------------------------------------------------------------- #
@app.route("/")
@app.route("/index", methods=['GET'])
def index() -> str:
    """
    Renders the index (home page) of the application

    :returns: str
    """
    return render_template('index.html', title='Home')


@app.route("/login", methods=['GET'])
def login_form() -> str:
    """
    Renders the login form using the form template and validation fields we've created using LoginForm

    :returns: str
    """
    form = LoginForm()
    return render_template('login_form.html', title='Login', form=form)


@app.route('/login', methods=['POST'])
def login() -> str:
    """
    Handles the login process using a POST request.

    This function processes and validates the submitted login form, checks the
    provided credentials against the stored hash in the database, and ensures
    the user credentials match. If validation fails at any point, an appropriate
    error response is returned.

    :raises ValidationError: If form validation fails.
    :raises DatabaseError: If an issue occurs when connecting or querying the database.

    :returns: If form validation fails, it returns a rendered HTML response with
              the form and errors to be displayed. If the user credentials are invalid,
              a string stating the issue is returned. Otherwise, the username and
              password entered by the user are returned as a formatted string.
    :rtype: str
    """
    form = LoginForm()

    if not form.validate_on_submit():
        # If validation detected any errors, return to the login_form page and include errors to display
        errors = form.errors
        return render_template('login_form.html', title='Login', form=form, errors=errors)

    # Extract username and password from form data
    username = form.username.data
    entered_password = form.password.data

    # Create an ephemeral connection to the DB and select the password for the user we've specified
    conn = get_db()
    cursor = conn.execute("SELECT password FROM students WHERE username = ?",
                          (username,))
    result = cursor.fetchone()

    if result is None:
        # Errors branch out and short circuit function
        return "User not found!"

    # If the result is found, store it in a variable
    stored_password = result[0]

    # Decrypt password hash to compare against the entered password
    if not bcrypt.check_password_hash(stored_password, entered_password):
        # Errors branch out and short circuit function
        return "Incorrect log in!"

    # Default path is our success path without failures
    return f"Username: {username}, Password: {entered_password}"


@app.route('/register', methods=['GET'])
def register_form() -> str:
    """
    Renders the register form using the form template and validation fields we've created using LoginForm

    :returns: str
    """
    form = LoginForm()
    return render_template('register_form.html', title='Register', form=form)


@app.route('/register', methods=['POST'])
def register() -> str:
    """
    Handles user registration requests.

    This function serves as a route for handling HTTP POST requests for user
    registration. It validates user input using a form object, hashes the user
    password for security, and stores the username and its hashed password in
    a database. In case the form validation fails, it returns the registration
    form template with the validation errors.

    :returns: If form validation fails, renders the registration form template
        with the related error messages. If registration is successful, returns
        a success message containing the username.
    """
    form = LoginForm()

    if not form.validate_on_submit():
        # If validation detected any errors, return to the login_form page and include errors to display
        errors = form.errors
        return render_template('register_form.html', title='Register', form=form, errors=errors)

    # Extract username and password from form data
    username = form.username.data
    password = form.password.data
    # Generate a hash by encrypting the entered password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Create an ephemeral connection to the DB
    conn = get_db()
    conn.execute(
        # Then insert the username and hashed_password we've specified
        "INSERT INTO students (username, password) VALUES (?, ?)",
        (username, hashed_password)
    )

    # Commit the transaction and display a success message to the user
    conn.commit()
    return f'{username} Added!'


@app.route("/students", methods=['GET'])
def employees() -> str:
    """
    Fetches all student records from the database, formats them as a list of dictionaries,
    and renders a web page to display the data.

    The student records are retrieved using an SQL query, and the results are
    processed to extract their username and password fields.
    The processed data is passed to the template rendering process.

    :rtype: str
    :return: Rendered HTML content displaying the formatted student data.
    """
    mytitle = "User Database Records" # This can be optionally set or commented out
    formatted_students = []

    # Create an ephemeral connection to the DB
    conn = get_db()
    # Then select all records from the students table
    cursor = conn.execute('SELECT * FROM students')
    all_students = cursor.fetchall()

    # Fetch returns a tuple (ID, USERNAME, PASSWORD)
    print(all_students)
    # Format tuples to a list of dicts using the previously initialized `formatted_students`
    for student in all_students:
        formatted_students.append(
            {"username":student[1], "password":student[2]}
        )

    print(formatted_students)
    # [{ username: "username", password: "password" }, ...]
    return render_template('dataexamples.html', title=mytitle, data=formatted_students)


@app.route("/init_db")
def init_db():
    """
    Initializes the database and creates the 'students' table if it does not already exist.

    This function connects to the database, ensures the existence of the 'students' table
    with appropriate fields (id, username, password), and commits the changes.

    :return: A success message indicating that the database and table were initialized.
    :rtype: str
    """
    # Create an ephemeral connection to the DB
    conn = get_db()
    # Then create our default table in the SQLite database if it doesn't already exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS students (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.commit()
    return "Database and 'students' table initialized."

# --------------------------------------------------------------------------------------- #
#                                    DB Connections                                       #
# --------------------------------------------------------------------------------------- #
def get_db() -> Connection:
    """
    Fetches and returns a database connection object. This function checks if the
    database connection already exists in the current application context. If not,
    it creates a new connection to the specified SQLite database and stores it in
    the context for reuse throughout the request lifecycle.

    :return: The active SQLite database connection object for the current context
    :rtype: Connection
    """
    # g is a special object Flask uses as a per-request global storage
    db = getattr(g, '_database', None)
    if db is None:
        # Create a connection and store in the _database field of g
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext # Register this function to run automatically when the app context ends
def close_connection(exception) -> None: # Decorator requires the signature to accept an exception arg
    """
    Close the database connection if it exists.

    This function ensures that the database connection is properly closed
    when the application context ends, preventing potential resource leaks.

    :return: None
    """
    print(exception)
    # g is a special object Flask uses as a per-request global storage
    db = getattr(g, '_database', None)
    if db is not None:
        # Release the database resources at the end of the request
        db.close()

# --------------------------------------------------------------------------------------- #
#                                        Startup                                          #
# --------------------------------------------------------------------------------------- #
if __name__ == "__main__":
    app.run()