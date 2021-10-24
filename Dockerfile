FROM ubuntu:latest

ENV PYTHONUNBUFFERED 1
ENV LANG C.UTF-8

RUN apt update && apt install -y python3 python3-pip
RUN pip3 install --upgrade pip

COPY ./requirements.txt .
RUN pip3 install -r requirements.txt --no-cache-dir

COPY . /app
EXPOSE 5000
WORKDIR /app

ENV DEBUG false
# ENV DB_HOST host.docker.internal
# ENV DB_PASSWORD 39yYg7sFKhVRH2z3
# ENV DB_PORT 5432

# ENTRYPOINT ["python3"]
# CMD ["/app/server/api.py"]