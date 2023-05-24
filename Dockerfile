FROM python:3-alpine

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY script.py .

CMD ["python3", "script.py"]
