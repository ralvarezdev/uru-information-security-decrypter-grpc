@echo off

REM Check if OpenSSL is installed
where openssl >nul 2>&1
if errorlevel 1 (
    echo Error: OpenSSL is not installed or not found in PATH.
    exit /b 1
)

REM Generate keys using OpenSSL
echo Generating RSA key pair...
openssl genpkey -algorithm rsa -out tender_private_key.pem
openssl pkey -in tender_private_key.pem -pubout -out tender_public_key.pem
echo Keys generated: tender_private_key.pem and tender_public_key.pem