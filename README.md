# RESUME OPTIMIZER BACKEND
This project is made on Django framework. This project works with frontend repository [RESUME OPTIMIZER FRONTEND](). 
Aim of this project is to **quickly** optimize the resume based on the provided job description so that it can pass through ATS test with the help of AI. 

## Frontend
Frontend for this project is available at [RESUME OPTIMIZER FRONTEND](https://github.com/rishabbahal9/Resume-optimizer-frontend.git).

## Running the application

1. Clone this repository.

2. Create a virtual environment inside root of the project.

```console
$ python -m venv .venv
```

(Make sure you have pyenv installed)

3. Activate virtual environment

```console
$ source .venv/bin/activate
```

For later if you want to exit virtual env `$ deactivate`

4. Install dependencies from requirements.txt

```console
$ pip install -r requirements.txt
```

upgrade the pip if you are asked to in terminal.

5. Make migrations and run server

```console
$ python manage.py makemigrations
$ python manage.py migrate --run-syncdb
$ python manage.py runserver
```

## How to fix Django cors error
https://dzone.com/articles/how-to-fix-django-cors-error

## Testing

To run tests:
```console
python manage.py test
```
For test coverage report
```console
coverage run --source='users' manage.py test && coverage report && coverage html
```

For test coverage report of multiple apps
```console
coverage run --source='users, your_app, your_app2' manage.py test && coverage report && coverage html
```

* https://www.youtube.com/watch?v=17KdirMbmHY
* https://github.com/jazzband/djangorestframework-simplejwt/blob/master/tests/test_authentication.py

## References
1. https://django-rest-framework-simplejwt.readthedocs.io/en/latest/
2. https://medium.com/django-rest/logout-django-rest-framework-eb1b53ac6d35
3. https://www.youtube.com/watch?v=PUzgZrS_piQ
