FROM python:3.13-slim

WORKDIR /app

COPY . .

RUN pip3 install -r requirements.txt

RUN chmod +x ./entrypoint.sh

ENTRYPOINT [ "./entrypoint.sh" ]
