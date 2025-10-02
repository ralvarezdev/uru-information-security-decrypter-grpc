@echo off
setlocal

REM Get the script directory
set "SCRIPT_DIR=%~dp0"

REM Protobuf-related paths
set "PROTO_PATH=%SCRIPT_DIR%\proto"
set "CERTIFICATE_PROTO_PATH=%SCRIPT_DIR%\certificate-grpc\proto"
set "PROTO_CERTIFICATE_PATH=%CERTIFICATE_PROTO_PATH%\ralvarezdev\certificate.proto"
set "PROTO_DECRYPTER_PATH=%PROTO_PATH%\ralvarezdev\decrypter.proto"
set "PROTO_OUT_PATH=%SCRIPT_DIR%\"

REM Activate the virtual environment
call .venv\Scripts\activate.bat

REM Create output directory if it doesn't exist
if not exist "%PROTO_OUT_PATH%" (
    mkdir "%PROTO_OUT_PATH%"
)

REM Check if the protobuffer files exist
if not exist "%PROTO_CERTIFICATE_PATH%" (
    echo Error: Protobuf file "%PROTO_CERTIFICATE_PATH%" not found!
    exit /b 1
)
if not exist "%PROTO_DECRYPTER_PATH%" (
    echo Error: Protobuf file "%PROTO_DECRYPTER_PATH%" not found!
    exit /b 1
)

REM Compile the protobuf file
python -m grpc_tools.protoc -I="%CERTIFICATE_PROTO_PATH%" --python_out="%PROTO_OUT_PATH%" --grpc_python_out="%PROTO_OUT_PATH%" "%PROTO_CERTIFICATE_PATH%"
python -m grpc_tools.protoc -I="%PROTO_PATH%" --python_out="%PROTO_OUT_PATH%" --grpc_python_out="%PROTO_OUT_PATH%" "%PROTO_DECRYPTER_PATH%"