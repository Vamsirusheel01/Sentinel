# Ensure we are in the script's directory for relative paths
Set-Location $PSScriptRoot

# Start Sentinel Brain (Server)
Start-Process powershell -ArgumentList "-NoExit -Command python brain\server.py"

# Start Sentinel Agent (Monitor)
Start-Process powershell -ArgumentList "-NoExit -Command python agent\monitor.py"

# Start Sentinel Dashboard (Vite)
Set-Location dashboard
Start-Process powershell -ArgumentList "-NoExit -Command npm run dev"
