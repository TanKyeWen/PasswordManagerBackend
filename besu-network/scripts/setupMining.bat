@echo off
echo === Besu Mining Setup ===

echo Stopping any running Besu instances...
taskkill /f /im besu.exe 2>nul || echo No Besu process found

echo Waiting...
timeout /t 2 /nobreak >nul

echo Starting Besu with mining enabled...

REM The miner address should be the authority address from your genesis.json
set MINER_ADDRESS=0xB7d84135999C320Ee6279C6c1396647AABFe7Cae

echo Miner Address: %MINER_ADDRESS%

REM Start Besu with mining enabled
besu --data-path=./data ^
     --genesis-file=./config/genesis.json ^
     --network-id=1337 ^
     --rpc-http-enabled ^
     --rpc-http-cors-origins="*" ^
     --host-allowlist="*" ^
     --rpc-http-port=8545 ^
     --p2p-port=30303 ^
     --miner-enabled ^
     --miner-coinbase=%MINER_ADDRESS%

echo Besu started with mining enabled!
echo Monitor the logs to see if blocks are being mined.
echo Press Ctrl+C to stop the node.

pause