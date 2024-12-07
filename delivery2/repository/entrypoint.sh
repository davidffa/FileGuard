#!/usr/bin/env bash

flask db init
flask db migrate
flask db upgrade

python3 app.py $MASTER_PASSWORD
