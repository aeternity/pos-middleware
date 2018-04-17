FROM python:3.6-alpine3.7

RUN apk update && \
  apk add --virtual build-deps gcc python-dev musl-dev && \
  apk add postgresql-dev

ADD requirements.txt /data/requirements.txt
ADD beer-aepp-pos.py /data/beer-aepp-pos.py

RUN pip install -r /data/requirements.txt

ENTRYPOINT [ "/data/beer-aepp-pos.py" ]