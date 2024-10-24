# ICS 2102 Auth
This repository contains the codebase for my ICS 2102 Web Dev Practical Exercise. The project is a todo list where each user has his/her own account where he/she manages their todos. A user can add, update or delete a todo and also update their profile information.


## API
```
/api/login  POST
{
    "username": "string",
    "password": "Sup3rStr0ng"
    "email": "example@example.com"
}

/api/signup POST
{
    "username": "string",
    "password": "Sup3rStr0ng"
    "email": "example@example.com"
}

/api/users  GET

/api/users/{id} GET

/api/users/{id} DELETE

/api/forgotpassword POST
{
    "email": "example@example.com"
}

/api/todos  POST
{
    "title": "string",
    "description": "string",
    "due_date": "YYYY-MM-DD"
}

/api/todos/{id} PUT
{
    "title": "string",
    "description": "string",
    "due_date": "YYYY-MM-DD"
}

/api/todos/{id} DELETE
```

## Technologies used
Python (Flask)

Jinja2 Templating Engine

HTML/CSS

PostgreSQL

SQLAlchemy

Pydantic

## How to run the project

```
$ git clone https://github.com/PMagombedze/ics-2102-Auth
$ cd ics-2102-Auth
$ python3 -m pip install -r requirements.txt
$ python3 app.py
```

The project will be served at __localhost:5000__, visit this address and yeah that's it!
