import serial
import serial.tools.list_ports
import wmi
import pythoncom
import time
import re
import requests
import threading
from datetime import datetime
from typing import Optional, Dict, Tuple
import logging
import sys

# Logging Setup
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', "%Y-%m-%d %H:%M:%S")
file_handler = logging.FileHandler('sms_service.log', encoding='utf-8')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

class NoEmojiFilter(logging.Filter):
    def filter(self, record):
        try:
            record.msg.encode(sys.stdout.encoding or 'utf-8')
            return True
        except UnicodeEncodeError:
            return False

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
console_handler.addFilter(NoEmojiFilter())
logger.addHandler(console_handler)

# Configuration
TELEGRAM_BOT_TOKEN = "xxx"
TELEGRAM_CHAT_ID = "xxx"
CONFIG = {
    "SERIAL_BAUDRATE": 115200,
    "SERIAL_TIMEOUT": 5,
    "HOTPLUG_POLL_INTERVAL": 15,
    "USSD_DELAY": 3,
    "DEBUG_ENABLED": False
}

logger.setLevel(logging.DEBUG if CONFIG["DEBUG_ENABLED"] else logging.INFO)

# Constants
USSD_CODES = {
    "dtac": b'AT+CUSD=1,"*102#",15\r\n',
    "ais": b'AT+CUSD=1,"*545#",15\r\n',
    "true": b'AT+CUSD=1,"*933#",15\r\n'
}

OPERATOR_MAPPING = {
    "dtac": "dtac",
    "happy": "dtac",
    "ais": "ais",
    "true": "true",
    "truemove": "true",
    "truemove h": "true"
}

TARGET_DEVICE_NAME = "HUAWEI Mobile Connect - 3G PC UI Interface"
port_lock = threading.Lock()

# Utility Functions
def decode_ussd(hex_str: str) -> str:
    """Decode USSD hex string to readable text"""
    logger.debug(f"Decoding USSD: {hex_str}")
    if not re.fullmatch(r'[0-9A-Fa-f]+', hex_str) or len(hex_str) < 4 or len(hex_str) % 2 != 0:
        logger.debug(f"Not valid hex, returning as-is: {hex_str}")
        return hex_str
    try:
        decoded = bytes.fromhex(hex_str).decode('utf-16-be')
        logger.debug(f"Successfully decoded USSD: {decoded}")
        return decoded
    except Exception as e:
        logger.error(f"Error decoding USSD: {e}")
        return hex_str

def decode_sms(text: str) -> str:
    """Decode SMS text (handle hex encoding)"""
    logger.debug(f"Decoding SMS: {text}")
    if text.isdigit():
        return text
    if re.fullmatch(r'[0-9A-Fa-f]+', text) and len(text) >= 4 and len(text) % 2 == 0:
        try:
            decoded = bytes.fromhex(text).decode('utf-16-be')
            logger.debug(f"Successfully decoded SMS: {decoded}")
            return decoded
        except Exception as e:
            logger.error(f"Error decoding SMS: {e}")
            return text
    return text

def extract_phone_number(decoded: str) -> str:
    """Extract phone number from decoded text"""
    logger.debug(f"Extracting phone number from: {decoded}")
    
    patterns = [r'(\+66\d{8,9})', r'(0\d{9})']
    for pattern in patterns:
        match = re.search(pattern, decoded)
        if match:
            phone = match.group(0)
            logger.debug(f"Found phone number: {phone}")
            return phone
    
    cleaned = re.sub(r'\D+', '', decoded)
    if len(cleaned) >= 10:
        phone = '0' + cleaned[1:10]
        logger.debug(f"Formatted phone number: {phone}")
        return phone
    
    logger.warning(f"Could not extract phone number from: {decoded}")
    return "ไม่พบเบอร์"

def send_to_telegram(message: str):
    """Send message to Telegram"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            logger.info(f"Telegram sent successfully: {message[:50]}...")
        else:
            logger.error(f"Telegram failed: {response.text}")
    except Exception as e:
        logger.error(f"Telegram error: {e}")

def send_sms_to_telegram(sender, timestamp, message, usb_port=None, phone_number=None):
    """Format and send SMS to Telegram"""
    usb_info = f"USB: {usb_port}" if usb_port else "USB: Unknown"
    text = f"📩 {phone_number or 'Unknown'} ({usb_info}): {message}"
    send_to_telegram(text)

class Modem:
    """Represents a single modem connection"""
    
    def __init__(self, port: str, usb_port: str, baudrate: int = CONFIG["SERIAL_BAUDRATE"]):
        self.port = port
        self.usb_port = usb_port
        self.baudrate = baudrate
        self.serial = None
        self.phone_number: Optional[str] = None
        self.operator: Optional[str] = None
        self.initialized: bool = False

    def connect(self) -> bool:
        """Connect to the modem"""
        with port_lock:
            try:
                if self.serial and self.serial.is_open:
                    self.serial.close()
                self.serial = serial.Serial(self.port, self.baudrate, timeout=CONFIG["SERIAL_TIMEOUT"])
                logger.debug(f"Connected to {self.port} (USB: {self.usb_port})")
                return True
            except serial.SerialException as e:
                if "PermissionError(13" in str(e):
                    return False
                logger.error(f"Failed to connect to {self.port} (USB: {self.usb_port}): {e}")
                return False

    def close(self):
        """Close modem connection"""
        if self.serial and self.serial.is_open:
            try:
                self.serial.close()
                logger.debug(f"Closed {self.port} (USB: {self.usb_port})")
            except Exception as e:
                logger.error(f"Error closing {self.port} (USB: {self.usb_port}): {e}")

    def send_command(self, command: bytes, delay: float = 0.5) -> str:
        """Send AT command to modem"""
        try:
            if not self.serial or not self.serial.is_open:
                logger.error(f"Port {self.port} (USB: {self.usb_port}) not open")
                return ""
            
            self.serial.write(command)
            logger.debug(f"Sent to {self.port} (USB: {self.usb_port}): {command}")
            time.sleep(delay)
            
            response = self.serial.read(self.serial.in_waiting).decode('ascii', errors='ignore')
            logger.debug(f"Response from {self.port} (USB: {self.usb_port}): {response}")
            return response
        except serial.SerialException as e:
            if "PermissionError(13" in str(e):
                return ""
            logger.error(f"Command failed on {self.port} (USB: {self.usb_port}): {e}")
            return ""

def initialize_modem(modem: Modem) -> bool:
    """Initialize modem with required AT commands"""
    if not modem.connect():
        return False
    
    try:
        if "OK" not in modem.send_command(b'AT\r\n'):
            logger.error(f"Modem {modem.port} (USB: {modem.usb_port}) not responding to AT")
            return False
        
        init_cmd = b'AT+CMGF=1;+CNMI=2,1,0,0,0;+CMEE=2;^USSDMODE=0;+CUSD=1\r\n'
        modem.send_command(init_cmd, delay=1.0)
        
        modem.initialized = True
        logger.info(f"Modem {modem.port} (USB: {modem.usb_port}) initialized successfully")
        return True
    finally:
        modem.close()

def delete_all_sms(modem: Modem):
    """Delete all stored SMS messages"""
    if not modem.connect():
        return
    try:
        modem.send_command(b'AT+CMGD=1,4\r\n', delay=2.0)
        logger.info(f"Deleted all SMS on {modem.port} (USB: {modem.usb_port})")
    finally:
        modem.close()

def get_network_operator(modem: Modem) -> Optional[str]:
    """Get network operator name"""
    if modem.operator:
        return modem.operator
    
    if not modem.connect():
        logger.error(f"Cannot connect to {modem.port} (USB: {modem.usb_port}) for operator check")
        return None
    
    try:
        response = modem.send_command(b'AT+COPS?\r\n', delay=0.5)
        logger.debug(f"Operator response from {modem.port} (USB: {modem.usb_port}): {response}")
        
        match = re.search(r'\+COPS: \d+,\d+,"([^"]+)",\d+', response)
        if match:
            operator = match.group(1).lower()
            modem.operator = operator
            logger.info(f"Found operator: {operator} on {modem.port} (USB: {modem.usb_port})")
            return operator
        
        logger.warning(f"No operator found on {modem.port} (USB: {modem.usb_port})")
        return None
    except Exception as e:
        logger.error(f"Error getting operator on {modem.port} (USB: {modem.usb_port}): {e}")
        return None
    finally:
        modem.close()

def check_ussd(modem: Modem, net: str, code: bytes) -> Optional[str]:
    """Check phone number via USSD"""
    logger.info(f"🔍 Checking {net} number on {modem.port} (USB: {modem.usb_port})")
    
    if not modem.connect():
        logger.error(f"Cannot connect to {modem.port} (USB: {modem.usb_port}) for USSD")
        return None
    
    try:
        response = modem.send_command(code, delay=CONFIG["USSD_DELAY"])
        logger.debug(f"USSD response from {net} on {modem.port} (USB: {modem.usb_port}): {response}")
        
        match = re.search(r'\+CUSD:\s*\d+,"([^"]+)",?', response)
        if match:
            hex_str = match.group(1)
            decoded = decode_ussd(hex_str)
            phone = extract_phone_number(decoded)
            
            if phone != "ไม่พบเบอร์":
                logger.info(f"✅ Found number {phone} from {net} USSD on {modem.port} (USB: {modem.usb_port})")
                return phone
            
            logger.warning(f"Could not extract number from {net} USSD: {decoded}")
        else:
            logger.warning(f"No CUSD response from {net} on {modem.port} (USB: {modem.usb_port})")
        
        return None
    finally:
        modem.close()

def get_phone_number(modem: Modem) -> Optional[str]:
    """Get phone number for the modem"""
    if not modem.connect():
        logger.error(f"Cannot connect to {modem.port} (USB: {modem.usb_port})")
        return None
    
    try:
        reg_response = modem.send_command(b'AT+CREG?\r\n', delay=0.5)
        if "+CREG: 0,0" in reg_response:
            logger.warning(f"Modem {modem.port} (USB: {modem.usb_port}) not registered to network")
            return None
        
        modem.close()
        
        operator = get_network_operator(modem)
        if not operator:
            logger.warning(f"Cannot identify operator for {modem.port} (USB: {modem.usb_port})")
            send_to_telegram(f"⚠️ USB: {modem.usb_port}: Cannot identify network operator")
            return None
        
        matched_operator = None
        for key, value in OPERATOR_MAPPING.items():
            if key in operator:
                matched_operator = value
                break
        
        if matched_operator not in USSD_CODES:
            logger.warning(f"Operator {operator} not supported on {modem.port} (USB: {modem.usb_port})")
            send_to_telegram(f"⚠️ USB: {modem.usb_port}: Operator {operator} not supported")
            return None
        
        logger.info(f"Getting phone number for {modem.port} (USB: {modem.usb_port}) ({matched_operator})")
        phone = check_ussd(modem, matched_operator, USSD_CODES[matched_operator])
        
        if not phone:
            logger.warning(f"❌ No phone number found via USSD on {modem.port} (USB: {modem.usb_port})")
        
        return phone
        
    except Exception as e:
        logger.error(f"Error in get_phone_number for {modem.port} (USB: {modem.usb_port}): {e}")
        return None
    finally:
        modem.close()

def read_sms(modem: Modem, stop_event: threading.Event):
    """Read incoming SMS messages"""
    logger.info(f"Starting SMS reader thread for {modem.port} (USB: {modem.usb_port})")
    
    if not modem.connect():
        logger.error(f"Cannot connect to {modem.port} (USB: {modem.usb_port}) for SMS reading")
        return
    
    try:
        while not stop_event.is_set():
            response = modem.send_command(b'', delay=0.5)
            
            if '+CMTI:' in response:
                match = re.search(r'\+CMTI:\s*"SM",(\d+)', response)
                if match:
                    index = match.group(1)
                    logger.info(f"New SMS at index {index} on {modem.port} (USB: {modem.usb_port})")
                    
                    res = modem.send_command(f'AT+CMGR={index};+CMGD={index}\r\n'.encode(), delay=1.0)
                    
                    sms_lines = res.split('\n')
                    for i, line in enumerate(sms_lines):
                        if '+CMGR:' in line:
                            match = re.match(r'\+CMGR:\s*"[^"]+","([^"]+)",[^,]*,"([^"]+)"', line)
                            if match:
                                sender = match.group(1)
                                timestamp = match.group(2)
                                message = sms_lines[i+1].strip() if i+1 < len(sms_lines) else ""
                                message = decode_sms(message)
                                
                                logger.info(f"SMS from {sender}: {message}")
                                send_sms_to_telegram(sender, timestamp, message, modem.usb_port, modem.phone_number)
                                break
            
            time.sleep(0.5)
            
    except Exception as e:
        logger.error(f"Error in SMS reader for {modem.port} (USB: {modem.usb_port}): {e}")
    finally:
        modem.close()
        logger.info(f"SMS reader thread stopped for {modem.port} (USB: {modem.usb_port})")

def find_huawei_ports():
    """Find all available Huawei modem ports with their USB port"""
    ports = []
    c = wmi.WMI()
    
    for port in serial.tools.list_ports.comports():
        if TARGET_DEVICE_NAME.lower() in port.description.lower():
            modem_info = {
                "com_port": port.device,
                "usb_port": None
            }
            
            if port.vid and port.pid:
                vid_str = f"VID_{port.vid:04X}"
                pid_str = f"PID_{port.pid:04X}"
                
                for dev in c.Win32_PnPEntity():
                    if dev.PNPDeviceID and vid_str in dev.PNPDeviceID and pid_str in dev.PNPDeviceID:
                        match = re.search(r"&0&(\d+)$", dev.PNPDeviceID)
                        if match:
                            modem_info["usb_port"] = match.group(1)
                        break
            
            ports.append((modem_info["com_port"], modem_info["usb_port"]))
    
    logger.debug(f"Found Huawei ports: {ports}")
    return ports

def monitor_modems(active_modems: Dict[str, Modem], modem_threads: Dict[str, Tuple]):
    """Monitor for modem hot-plug events"""
    logger.info("Starting modem monitor")
    
    while True:
        try:
            pythoncom.CoInitialize()  # Initialize COM for WMI in thread
            current_ports = set()
            c = wmi.WMI()
            for port in serial.tools.list_ports.comports():
                if TARGET_DEVICE_NAME.lower() in port.description.lower():
                    usb_port = None
                    if port.vid and port.pid:
                        vid_str = f"VID_{port.vid:04X}"
                        pid_str = f"PID_{port.pid:04X}"
                        for dev in c.Win32_PnPEntity():
                            if dev.PNPDeviceID and vid_str in dev.PNPDeviceID and pid_str in dev.PNPDeviceID:
                                match = re.search(r"&0&(\d+)$", dev.PNPDeviceID)
                                if match:
                                    usb_port = match.group(1)
                                break
                    current_ports.add((port.device, usb_port))
            
            active_ports = set((modem.port, modem.usb_port) for modem in active_modems.values())
            
            new_ports = current_ports - active_ports
            for port, usb_port in new_ports:
                port_key = f"{port}_{usb_port or 'unknown'}"
                if port_key in modem_threads:
                    logger.debug(f"Port {port} (USB: {usb_port}) thread already exists, skipping")
                    continue
                
                logger.info(f"New modem detected: {port} (USB: {usb_port})")
                modem = Modem(port, usb_port)
                
                if initialize_modem(modem):
                    phone_number = get_phone_number(modem)
                    modem.phone_number = phone_number
                    
                    stop_event = threading.Event()
                    thread = threading.Thread(target=read_sms, args=(modem, stop_event))
                    thread.daemon = True
                    
                    modem_threads[port_key] = (thread, stop_event)
                    active_modems[port_key] = modem
                    thread.start()
                    
                    usb_info = f"USB: {usb_port}" if usb_port else "USB: Unknown"
                    send_to_telegram(f"🟢 {usb_info}: {phone_number or 'Unknown'}")
                    logger.info(f"Started monitoring {port} (USB: {usb_port}): {phone_number or 'Unknown'}")
            
            removed_ports = active_ports - current_ports
            for port, usb_port in removed_ports:
                port_key = f"{port}_{usb_port or 'unknown'}"
                logger.info(f"Modem removed: {port} (USB: {usb_port})")
                
                modem = active_modems.pop(port_key, None)
                thread, stop_event = modem_threads.pop(port_key, (None, None))
                
                if stop_event:
                    stop_event.set()
                    if thread:
                        thread.join(timeout=3)
                        if thread.is_alive():
                            logger.warning(f"Thread for {port} (USB: {usb_port}) did not stop within timeout")
                        else:
                            logger.info(f"Thread for {port} (USB: {usb_port}) stopped successfully")
                
                usb_info = f"USB: {usb_port}" if usb_port else "USB: Unknown"
                send_to_telegram(f"🔴 {usb_info} removed")
            
            time.sleep(CONFIG["HOTPLUG_POLL_INTERVAL"])
            
        except Exception as e:
            logger.error(f"Error in monitor_modems: {e}")
            time.sleep(5)
        finally:
            pythoncom.CoUninitialize()  # Clean up COM

def initialize_and_setup_modem(modem: Modem):
    """Initialize modem, get phone number, and delete all SMS in one thread"""
    logger.info(f"Initializing and setting up modem: {modem.port} (USB: {modem.usb_port})")
    if initialize_modem(modem):
        modem.phone_number = get_phone_number(modem)
        if modem.initialized:
            delete_all_sms(modem)
    else:
        modem.initialized = False

def main():
    """Main function"""
    print("🚀 Starting SMS Service...")
    logger.info("SMS Service starting...")
    
    active_modems = {}
    modem_threads = {}
    
    ports = find_huawei_ports()
    if not ports:
        print("❌ No Huawei modems found")
        logger.error("No Huawei 3G modems found")
        return
    
    print(f"Found {len(ports)} modem(s): {[f'USB: {usb}' for _, usb in ports]}")
    logger.info(f"Found modems: {ports}")
    
    modem_info = []
    threads = []
    
    for port, usb_port in ports:
        logger.info(f"Preparing modem: {port} (USB: {usb_port})")
        modem = Modem(port, usb_port)
        port_key = f"{port}_{usb_port or 'unknown'}"
        active_modems[port_key] = modem
        
        thread = threading.Thread(target=initialize_and_setup_modem, args=(modem,))
        thread.daemon = True
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    for port, usb_port in ports:
        port_key = f"{port}_{usb_port or 'unknown'}"
        if port_key not in active_modems:
            logger.error(f"Port {port} (USB: {usb_port}) not found in active_modems")
            continue
        
        modem = active_modems[port_key]
        if modem.initialized:
            usb_info = f"USB: {usb_port}" if usb_port else "USB: Unknown"
            print(f"🟢 Modem ready: {usb_info} ({modem.phone_number or 'No number'})")
            modem_info.append((usb_port, modem.phone_number or "No number"))
            
            stop_event = threading.Event()
            thread = threading.Thread(target=read_sms, args=(modem, stop_event))
            thread.daemon = True
            modem_threads[port_key] = (thread, stop_event)
            thread.start()
        else:
            usb_info = f"USB: {usb_port}" if usb_port else "USB: Unknown"
            print(f"🔴 Modem not responding: {usb_info}")
            modem_info.append((usb_port, "Not responding"))
    
    summary = "\n".join([f"📡 SMS Service Started"] + [f"USB: {usb}: {n}" for usb, n in modem_info])
    send_to_telegram(summary)
    
    monitor_thread = threading.Thread(target=monitor_modems, args=(active_modems, modem_threads))
    monitor_thread.daemon = True
    monitor_thread.start()
    
    print("✅ SMS Service running. Press Ctrl+C to stop.")
    logger.info("SMS Service is now running")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping SMS Service...")
        logger.info("SMS Service stopping...")
        
        for port_key, (thread, stop_event) in list(modem_threads.items()):
            port, usb_port = port_key.split('_', 1)
            logger.info(f"Stopping thread for {port} (USB: {usb_port})")
            stop_event.set()
            thread.join(timeout=3)
            if thread.is_alive():
                logger.warning(f"Thread for {port} (USB: {usb_port}) did not stop cleanly")
            else:
                logger.info(f"Thread for {port} (USB: {usb_port}) stopped")
        
        print("👋 SMS Service stopped")
        logger.info("SMS Service stopped")

if __name__ == "__main__":
    main()
