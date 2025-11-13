# Flask API Example

A Flask application that uses: 
* WTForms to retrieve forms and validate inputs
* Bcrypt to encrypt/decrypt entered passwords
* SQLite to store/retrieve student information

## Endpoints

* `/index` or `/`: Main entrypoint for application, contains a guide for other endpoints
* `/setup_db`: Must be used before operating on student data
* `/register`: Used to validate, encrypt, and register student data to the pre-initialized database
* `/login`: Used to verify that student login information is correct
* `/students`: Used to return a list of the current student usernames and passwords

## Verification

* Username: Between 2-25 characters and can only contain letters, numbers, and underscores.
* Password: Atleast 8 characters and must be a combination of both letters and numbers.