# 📱 SMS Service v8.4

An advanced SMS forwarding service that reads SMS messages from Huawei modems and forwards them to Telegram with intelligent OTP detection and filtering.

## ✨ Features

### 🎯 Smart OTP Detection
- **Intelligent Pattern Recognition**: Automatically detects OTP codes from various sources
- **Multi-Language Support**: Thai, English, Japanese character recognition
- **Multiple Formats**: Supports various OTP formats (Google, Facebook, LINE, banking, etc.)
- **OTP-Only Mode**: Option to forward only security-relevant messages

### 📡 Multi-Modem Support
- **Automatic Discovery**: Detects all connected Huawei modems
- **Concurrent Processing**: Handles multiple modems simultaneously
- **Network Operator Detection**: Auto-detects AIS, DTAC, True networks
- **Phone Number Extraction**: Retrieves phone numbers via USSD

### 🚀 Advanced Features
- **Batch Processing**: Groups messages for efficient delivery
- **Real-time Monitoring**: Continuous SMS monitoring
- **Telegram Integration**: Instant notifications via Telegram Bot
- **Comprehensive Logging**: Detailed logs with configurable verbosity
- **Graceful Shutdown**: Clean resource management

## 🔧 Installation & Setup

### Prerequisites
```bash
pip install pyserial requests
```

### Hardware Requirements
- Huawei USB modems (3G/4G)
- Windows/Linux system with USB ports
- Active SIM cards with SMS capability

### Configuration

Edit the `Config` class in the script:

```python
@dataclass
class Config:
    TELEGRAM_BOT_TOKEN: str = "YOUR_BOT_TOKEN"
    TELEGRAM_CHAT_ID: str = "YOUR_CHAT_ID"
    OTP_ONLY_MODE: bool = True  # True = OTP only, False = all messages
    DEBUG_ENABLED: bool = False
    BATCH_TIMEOUT: int = 15
```

### Telegram Bot Setup

1. Create a bot via [@BotFather](https://t.me/botfather)
2. Get your bot token
3. Get your chat ID (send a message to [@userinfobot](https://t.me/userinfobot))
4. Update the configuration with your credentials

## 🚀 Usage

### Basic Usage
```bash
python smsV8.4.py
```

### Operating Modes

#### OTP-Only Mode (Default)
```python
OTP_ONLY_MODE: bool = True
```
- Only forwards SMS containing OTP/verification codes
- Reduces notification noise
- Focuses on security-relevant messages

#### All Messages Mode
```python
OTP_ONLY_MODE: bool = False
```
- Forwards all received SMS messages
- Traditional behavior for complete monitoring

## 🔍 OTP Detection Patterns

The service recognizes OTP codes from:

### Supported Services
- **Google**: `G-123456`
- **Facebook**: `<#> 123456`
- **LINE**: `Please enter 123456 into LINE`
- **Banking**: Various Thai bank formats
- **General**: `Your verification code is 123456`

### Supported Formats
- **Thai**: `รหัส OTP: 123456`, `โค้ดยืนยัน 123456`
- **English**: `verification code: 123456`, `OTP: 123456`
- **Formatted**: `123-456`, `12-34-56`
- **Standalone**: 4-8 digit codes

## 📊 Message Format

### Startup Notification
```
📡 SMS Service Started (OTP Only)
0812345678 #1
0823456789 #2
0834567890 #3
```

### OTP Messages
```
0812345678 #1: 123456
0823456789 #2: G-789012
0834567890 #3: 💤
```

### All Messages Mode
```
0812345678 #1: Your bank balance is...
0823456789 #2: G-789012
0834567890 #3: 💤
```

## 🛠️ Advanced Configuration

### Serial Port Settings
```python
SERIAL_BAUDRATE: int = 115200
SERIAL_TIMEOUT: int = 5
```

### Network Settings
```python
USSD_DELAY: int = 10
NETWORK_SEARCH_DELAY: int = 15
```

### Batch Processing
```python
BATCH_TIMEOUT: int = 15  # seconds to wait for all modems
```

## 📋 Supported Networks

| Operator | USSD Code | Auto-Detection |
|----------|-----------|----------------|
| AIS | *545# | ✅ |
| DTAC/Happy | *102# | ✅ |
| True/TrueMove H | *933# | ✅ |

## 🐛 Troubleshooting

### Common Issues

#### No Modems Found
```
❌ No Huawei modems found
```
**Solution**: Check USB connections and driver installation

#### Permission Errors
```
PermissionError(13, 'Access is denied')
```
**Solution**: Run as administrator or check port permissions

#### Modem Not Responding
```
🔴 Modem not responding: COM3
```
**Solution**: Check SIM card, network registration, and modem status

### Debug Mode
Enable detailed logging:
```python
DEBUG_ENABLED: bool = True
```

### Log Files
Check `sms_service.log` for detailed operation logs.

## 📁 File Structure

```
├── smsV8.4.py          # Main application
├── sms_service.log     # Runtime logs
└── README.md           # This file
```

## 🔐 Security Considerations

- Keep Telegram bot token secure
- Use OTP-only mode to reduce data exposure
- Monitor logs for suspicious activity
- Regularly update credentials

## 🚦 Service Management

### Starting the Service
```bash
python smsV8.4.py
```

### Stopping the Service
Press `Ctrl+C` for graceful shutdown

### Background Running (Linux)
```bash
nohup python smsV8.4.py &
```

### Windows Service
Consider using tools like NSSM for Windows service installation.

## 📈 Performance

### Typical Performance
- **Response Time**: <1 second for OTP detection
- **Throughput**: Handles 10+ modems simultaneously
- **Memory Usage**: ~50MB for multiple modems
- **CPU Usage**: <5% during normal operation

### Optimization Tips
- Use OTP-only mode for better performance
- Adjust batch timeout based on modem count
- Enable debug mode only when troubleshooting

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with actual hardware
5. Submit a pull request

## 📄 License

This project is provided as-is for educational and personal use.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review log files
3. Test with single modem first
4. Verify hardware connections

## 🔄 Version History

- **v8.4**: OTP-only mode, enhanced pattern recognition
- **v8.3**: Multi-modem batch processing
- **v8.2**: Improved error handling
- **v8.1**: Network operator detection
- **v8.0**: Complete rewrite with modern architecture

---

**⚠️ Important**: This software is designed for legitimate SMS monitoring purposes. Ensure compliance with local laws and regulations regarding SMS interception and forwarding.
