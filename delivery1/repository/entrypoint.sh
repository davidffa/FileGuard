#!/usr/bin/env bash

flask db init
flask db migrate
flask db upgrade

flask run -h 0.0.0.0 -p 8000
