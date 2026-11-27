# Shared headless Chromium with CDP for the playwright MCP and the login_fill sink.
# Equivalent of start-cdp-chrome.sh: same flags, Windows paths.
$ErrorActionPreference = "Stop"

$Chrome = Join-Path $env:ProgramFiles "Google\Chrome\Application\chrome.exe"
if (-not (Test-Path $Chrome)) {
    $Chrome = Join-Path ${env:ProgramFiles(x86)} "Google\Chrome\Application\chrome.exe"
}
if (-not (Test-Path $Chrome)) {
    throw "Chrome not found; install Google Chrome or edit this script."
}

$Profile = Join-Path $env:TEMP "opencode\pw-cdp-profile"
New-Item -ItemType Directory -Force -Path $Profile | Out-Null

$arguments = @(
    "--headless=new",
    "--remote-debugging-port=9222",
    "--remote-debugging-address=127.0.0.1",
    "--user-data-dir=$Profile",
    "--no-first-run",
    "--no-default-browser-check",
    "--ignore-certificate-errors",
    "--allow-running-insecure-content",
    "--disable-features=HttpsUpgrades,HttpsOnlyMode,HttpsFirstModeV2,HttpsFirstModeV2ForTypingNavigation,HttpsFirstBalancedMode,AutoUpgradeAllowedInMainframe",
    "about:blank"
)

Start-Process -FilePath $Chrome -ArgumentList $arguments -WindowStyle Hidden
Start-Sleep -Seconds 2

try {
    Invoke-RestMethod -Uri "http://127.0.0.1:9222/json/version" | ConvertTo-Json -Depth 3
} catch {
    throw "CDP did not start on 127.0.0.1:9222: $_"
}
