@echo off
echo Starting local Docker containers...
docker compose up -d

echo.
echo Waiting for services to start...
timeout /t 5

echo.
echo Starting Ngrok on port 5173...
echo Ensure you have authenticated with Ngrok first: ngrok config add-authtoken ^<token^>
echo A new window will pop up with your HTTPS tunnel URL.
start cmd /k "ngrok http 5173"
