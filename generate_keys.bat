@echo off

REM Check if OpenSSL is installed
where openssl >nul 2>&1
if errorlevel 1 (
    echo Error: OpenSSL is not installed or not found in PATH.
    exit /b 1
)

REM Generate keys using OpenSSL
echo Generating Ed25519 key pair...
openssl genpkey -algorithm ed25519 -out private.key
openssl pkey -in private.key -pubout -out public.key
echo Keys generated: private.key and public.key