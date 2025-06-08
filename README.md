# SMS Service

A Python-based SMS service for Huawei 3G modems to receive SMS messages and forward them to Telegram.

## Features
- Detects and monitors Huawei 3G modems via USB ports.
- Retrieves phone numbers using USSD codes for supported operators (dtac, ais, true).
- Reads incoming SMS and forwards them to a Telegram chat.
- Supports hot-plugging of modems with automatic detection and initialization.
- Logs operations to a file (`sms_service.log`) and console.

## Requirements
- Python 3.6+
- Libraries: `pyserial`, `wmi`, `requests`
- Windows OS (for WMI-based USB detection)
- Huawei 3G modem with a SIM card
- Telegram bot token and chat ID

## Installation
1. Clone or download the repository.
2. Install dependencies:
   ```bash
   pip install pyserial wmi requests
   ```
3. Update `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in `smsV7_1.py` with your Telegram bot credentials.

## Usage
1. Connect Huawei 3G modem(s) to your computer.
2. Run the script:
   ```bash
   python smsV7_1.py
   ```
3. The service will:
   - Detect connected modems.
   - Initialize modems and retrieve phone numbers via USSD.
   - Monitor for new SMS and forward them to the configured Telegram chat.
   - Handle modem hot-plugging (connect/disconnect).
4. Press `Ctrl+C` to stop the service.

## Configuration
Edit the `CONFIG` dictionary in `smsV7_1.py`:
- `SERIAL_BAUDRATE`: Modem baud rate (default: 115200).
- `SERIAL_TIMEOUT`: Serial read timeout in seconds (default: 5).
- `HOTPLUG_POLL_INTERVAL`: Interval for checking modem connections (default: 15 seconds).
- `USSD_DELAY`: Delay after sending USSD commands (default: 3 seconds).
- `DEBUG_ENABLED`: Enable debug logging (default: False).

## Logging
- Logs are saved to `sms_service.log`.
- Console output includes emoji indicators for status updates.
- Debug logs are enabled if `DEBUG_ENABLED` is set to `True`.

## Notes
- Supported operators: dtac, ais, true.
- Ensure the modem is not in use by other applications.
- The script requires administrative privileges for WMI access on Windows.
