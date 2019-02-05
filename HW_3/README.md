# Scoring API

## Установка

Требует Python 3.7+

```
git clone git@github.com:AAAleg/otus_homeworks.git
cd otus_homeworks/HW_3
python3 -m venv env
```

## Использование

```
Usage: api.py [options]

Options:
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  
  -l LOG, --log=LOG 
```

По умолчанию стартует HTTP-сервер на порту 8080, а логи пишет в консоль.

Пример запроса к серверу:

```
$ curl -X POST  -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "user", "method": "clients_interests", "token": "14d4217f90b03773f7b7ae3f3c922fbc10bb195306182acb9217897608fc82df559e27b8fb8e7d013883ea23739cffe9ef5d1b58daba573784ecebb4ebcfef50", "arguments": {"client_ids": [1,2,3,4], "date": "24.12.2018"}}' http://127.0.0.1:8080/method/
```

## Разработка

Зависимости:

```
env/bin/pip install -r requirements.txt
```

Линтинг:

```
env/bin/pylint --rcfile=.pylintrc scoring
env/bin/flake8 scoring
```
