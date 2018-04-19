FROM python:3-alpine

RUN apk update && \
  apk add --virtual build-deps gcc python-dev musl-dev && \
  apk add postgresql-dev

ADD requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

ADD . /app
WORKDIR /app

ENTRYPOINT [ "./beer-aepp-pos.py" ]
CMD [ "start" ]
