# IntruAlert: High-Performance Network Intrusion Detection Engine (NIDS)

## 📖 Project Overview
IntruAlert is a high-performance **Network Intrusion Detection System (NIDS)** designed to analyse real-time network traffic, detect malicious activities, and alert users through an interactive dashboard. It ensures minimal impact on network performance while providing robust security monitoring.

## 🚀 Features
- **Real-Time Traffic Analysis**: Captures and inspects network packets on TCP, UDP, and ICMP protocols.
- **Protocol Analysis**: Classifies incoming traffic by protocol type.
- **Attack and Probe Detection**: Detects known attack patterns using signature-based detection.
- **Web-Based Dashboard**: Displays live threat summaries and attack logs.
- **WebSocket Communication**: Provides real-time data updates to the frontend.

## 📂 Project Structure
```
├── main.go              # Backend server and packet processing logic
├── dashboard.html       # Real-time monitoring dashboard
├── login.html           # User authentication interface
├── script.js            # WebSocket and UI interaction scripts
├── styles.css           # Custom styling for the frontend
├── signatures.json      # Attack signature patterns
├── config.json          # System configuration settings
├── attack_logs.json     # Logs of detected attacks
├── README.md            # Project documentation
```

## ⚙️ Installation & Setup

### Prerequisites
- Go 1.18 or higher
- Node.js (for frontend development, if needed)
- libpcap (for packet capture)

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/intrualert.git
cd intrualert

# Install dependencies
go mod tidy
```

### Run the Application
```bash
# Run the NIDS server
go run main.go
```

## 🛠️ Configuration
Modify the `config.json` file to adjust system settings:
```json
{
    "interfaces": ["\\Device\\NPF_Loopback"],
    "log_level": "INFO",
    "packet_types": ["TCP", "UDP", "ICMP"],
    "signature_file": "signatures.json"
}
```

## 📊 Dashboard Access
- Open your browser and navigate to: `http://localhost:8080`
- **Login Credentials:**
  - **Username:** `admin`
  - **Password:** `password`

## 🛡️ Attack Detection
Attack signatures are defined in `signatures.json`:
```json
{
  "id": "1",
  "description": "SYN attack",
  "pattern": "^SYN$",
  "severity": "High",
  "protocol": "TCP"
}
```

## 🔑 Authentication
- Basic session-based login system.
- Session management using cookies.

## 📢 Real-Time Alerts
- Uses WebSocket (`/ws`) to send real-time attack logs and threat summaries to the dashboard.

## 🧪 Testing
To simulate traffic, use tools like `Scapy` or `hping3`:
```python
from scapy.all import *
send(IP(dst="127.0.0.1")/TCP(dport=80, flags="S"))
```

## 🤝 Contribution
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature`).
3. Commit your changes (`git commit -m 'Add feature'`).
4. Push to the branch (`git push origin feature`).
5. Open a Pull Request.

## 📄 License
This project is proprietary and all rights are reserved. Please contact the project owner for licensing information.

## 📧 Contact
For any inquiries, feel free to reach out:
- **Email:** gaurav18rahul7@gmail.com
- **GitHub:** [gauravrahul](https://github.com/gauravrahul)

---

**IntruAlert** – Securing Networks in Real-Time 🔐

