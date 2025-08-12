@echo off
echo === Besu Mining Setup ===

echo Stopping any running Besu instances...
taskkill /f /im besu.exe 2>nul || echo No Besu process found

echo Waiting...
timeout /t 2 /nobreak >nul

echo Starting Besu with mining enabled...

REM The miner address should be the authority address from your genesis.json
set MINER_ADDRESS=0x578845f5b8ff7d173df6092d71705e29823a3f40

echo Miner Address: %MINER_ADDRESS%

REM Start Besu with mining enabled
besu --data-path=besu-network/data ^
     --genesis-file=besu-network/config/genesis.json ^
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