@echo off
echo Starting ML Pipeline Service...
cd ml-api
py -m venv venv
call venv\Scripts\activate.bat
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
