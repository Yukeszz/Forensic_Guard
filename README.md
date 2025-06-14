🛡️ Forensic_Guard

Forensic_Guard is a Python-based real-time forensic data collector and intrusion pattern monitor. It captures system, file, and network activities, detects suspicious behaviors like brute-force or DoS attacks, logs digital evidence, and sends alerts via email or SMS.



🚀 Features

- Real-time monitoring of:
  - System logs
  - File access events
  - Network activity
- Intrusion detection:
  - Brute-force login attempts
  - DoS attack patterns
  - File tampering
- Evidence logging and report generation
- Alerts via email and optional SMS
- Modular and multithreaded design
- Lightweight, runs fully in VS Code



📦 Installation


Clone the repository
git clone https://github.com/your-username/ForensicaGuard.git
cd ForensicaGuard

(Optional) Set up a virtual environment
python -m venv venv
source venv/bin/activate       # On Windows use: venv\Scripts\activate

Install required Python packages
pip install -r requirements.txt


Configuration - API Keys / Credentials
1. Email Alerts (Gmail)
 Go to Google Account Security Settings
2. Enable 2-Step Verification
3. Click App Passwords and generate one for "Mail"


🏃‍♀️ How to Run
1. Make sure you have Python installed.
2. Run the main script:
```python forensicaguard.py```
{
  "email": "sender_email@example.com",
  "password": "your_email_app_password",
  "receiver_email": "receiver_email@example.com"
}



