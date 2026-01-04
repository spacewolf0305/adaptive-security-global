import os
import gradio as gr
import matplotlib
matplotlib.use('Agg')  # <--- CRITICAL: Prevents crash on Cloud servers
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import requests
import seaborn as sns
import random
import uuid
import base64
import sqlite3
import time
from collections import deque
from fpdf import FPDF
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ==========================================
# 1. NEW FEATURES (Database, PDF, Rate Limit)
# ==========================================

# --- A. RATE LIMITER ---
RATE_LIMIT_DATA = {}
MAX_REQUESTS = 4
TIME_WINDOW = 10  # Seconds

def check_rate_limit(ip_address):
    current_time = time.time()
    if ip_address not in RATE_LIMIT_DATA:
        RATE_LIMIT_DATA[ip_address] = deque()
    
    # Clean old timestamps
    while RATE_LIMIT_DATA[ip_address] and RATE_LIMIT_DATA[ip_address][0] < current_time - TIME_WINDOW:
        RATE_LIMIT_DATA[ip_address].popleft()
        
    if len(RATE_LIMIT_DATA[ip_address]) >= MAX_REQUESTS:
        return True # BLOCKED
    
    RATE_LIMIT_DATA[ip_address].append(current_time)
    return False # ALLOWED

# --- B. DATABASE (Admin Logs) ---
def init_db():
    conn = sqlite3.connect('security_logs.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (timestamp TEXT, ip TEXT, country TEXT, risk_score INTEGER, verdict TEXT)''')
    conn.commit()
    conn.close()

init_db()

def log_to_db(ip, country, score, verdict):
    conn = sqlite3.connect('security_logs.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs VALUES (datetime('now'), ?, ?, ?, ?)", 
              (ip, country, score, verdict))
    conn.commit()
    conn.close()

def fetch_all_logs():
    conn = sqlite3.connect('security_logs.db')
    df = pd.read_sql_query("SELECT * FROM logs ORDER BY timestamp DESC", conn)
    conn.close()
    return df

# --- C. PDF GENERATOR ---
def generate_pdf_report(ip, country, verdict, details):
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Adaptive Security Forensic Report", ln=1, align='C')
        pdf.line(10, 20, 200, 20)
        pdf.ln(20)
        
        pdf.set_font("Arial", 'B', size=12)
        pdf.cell(200, 10, txt=f"Target IP: {ip}", ln=1)
        pdf.cell(200, 10, txt=f"Location: {country}", ln=1)
        pdf.cell(200, 10, txt=f"Final Verdict: {verdict}", ln=1)
        pdf.ln(10)
        
        pdf.set_font("Arial", size=10)
        # Clean text to prevent unicode errors in basic PDF
        clean_details = details.encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 10, txt=clean_details)
        
        filename = f"report_{uuid.uuid4().hex[:6]}.pdf"
        pdf.output(filename)
        return filename
    except Exception as e:
        return f"Error generating PDF: {str(e)}"

# ==========================================
# 2. CRYPTOGRAPHY ENGINE
# ==========================================
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key, pem_private.decode(), pem_public.decode()

def simulate_crypto_auth(username, use_wrong_key=False):
    log = []
    log.append(f"🔵 LOGIN ATTEMPT: {username}")
    
    priv_key, pub_key, priv_str, pub_str = generate_key_pair()
    challenge = f"CHALLENGE_{uuid.uuid4().hex[:8]}"
    challenge_bytes = challenge.encode()
    log.append(f"✅ Server Challenge: '{challenge}'")
    
    try:
        signer_key = priv_key if not use_wrong_key else rsa.generate_private_key(65537, 2048)
        signature = signer_key.sign(
            challenge_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        pub_key.verify(
            signature,
            challenge_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return "\n".join(log) + "\n✅ VERIFIED", "✅ SUCCESS"
    except:
        return "\n".join(log) + "\n🚫 SIGNATURE MISMATCH", "🚫 FAILED"

# ==========================================
# 3. AI & CLOUD ENGINE (Global Version)
# ==========================================

# 🌍 THE FULL LIST OF COUNTRIES (Global Support)
ALL_COUNTRIES = [
    "Afghanistan", "Albania", "Algeria", "Andorra", "Angola", "Antigua and Barbuda", "Argentina", "Armenia", "Australia", "Austria", "Azerbaijan",
    "Bahamas", "Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium", "Belize", "Benin", "Bhutan", "Bolivia", "Bosnia and Herzegovina", "Botswana", "Brazil", "Brunei", "Bulgaria", "Burkina Faso", "Burundi",
    "Cabo Verde", "Cambodia", "Cameroon", "Canada", "Central African Republic", "Chad", "Chile", "China", "Colombia", "Comoros", "Congo (Congo-Brazzaville)", "Costa Rica", "Croatia", "Cuba", "Cyprus", "Czechia (Czech Republic)",
    "Democratic Republic of the Congo", "Denmark", "Djibouti", "Dominica", "Dominican Republic",
    "Ecuador", "Egypt", "El Salvador", "Equatorial Guinea", "Eritrea", "Estonia", "Eswatini", "Ethiopia",
    "Fiji", "Finland", "France",
    "Gabon", "Gambia", "Georgia", "Germany", "Ghana", "Greece", "Grenada", "Guatemala", "Guinea", "Guinea-Bissau", "Guyana",
    "Haiti", "Holy See", "Honduras", "Hungary",
    "Iceland", "India", "Indonesia", "Iran", "Iraq", "Ireland", "Israel", "Italy",
    "Jamaica", "Japan", "Jordan",
    "Kazakhstan", "Kenya", "Kiribati", "Kuwait", "Kyrgyzstan",
    "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libya", "Liechtenstein", "Lithuania", "Luxembourg",
    "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali", "Malta", "Marshall Islands", "Mauritania", "Mauritius", "Mexico", "Micronesia", "Moldova", "Monaco", "Mongolia", "Montenegro", "Morocco", "Mozambique", "Myanmar (formerly Burma)",
    "Namibia", "Nauru", "Nepal", "Netherlands", "New Zealand", "Nicaragua", "Niger", "Nigeria", "North Korea", "North Macedonia", "Norway",
    "Oman",
    "Pakistan", "Palau", "Palestine State", "Panama", "Papua New Guinea", "Paraguay", "Peru", "Philippines", "Poland", "Portugal",
    "Qatar",
    "Romania", "Russia", "Rwanda",
    "Saint Kitts and Nevis", "Saint Lucia", "Saint Vincent and the Grenadines", "Samoa", "San Marino", "Sao Tome and Principe", "Saudi Arabia", "Senegal", "Serbia", "Seychelles", "Sierra Leone", "Singapore", "Slovakia", "Slovenia", "Solomon Islands", "Somalia", "South Africa", "South Korea", "South Sudan", "Spain", "Sri Lanka", "Sudan", "Suriname", "Sweden", "Switzerland", "Syria",
    "Tajikistan", "Tanzania", "Thailand", "Timor-Leste", "Togo", "Tonga", "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan", "Tuvalu",
    "Uganda", "Ukraine", "United Arab Emirates", "United Kingdom", "United States", "Uruguay", "Uzbekistan",
    "Vanuatu", "Venezuela", "Vietnam",
    "Yemen",
    "Zambia", "Zimbabwe",
    "Unknown"
]

def train_ai_model():
    print("🌍 Training AI on Global Dataset...")
    data = []
    
    # 1. ENCODE THE FULL LIST FIRST
    le = LabelEncoder()
    le.fit(ALL_COUNTRIES + ['Unknown'])
    
    # 2. GENERATE SYNTHETIC DATA
    for _ in range(2000):
        is_attacker = random.random() < 0.05
        
        if is_attacker:
            country = random.choice(['China', 'Russia', 'Iran', 'North Korea', 'Unknown', 'Brazil', 'Nigeria'])
            speed = random.choice([20, 140]) 
            hour = random.choice([0, 1, 2, 3, 23])
            vpn = 1
            device = 0
        else:
            country = random.choice(ALL_COUNTRIES)
            speed = int(np.random.normal(60, 10))
            hour = random.randint(8, 22)
            vpn = 0
            device = 1
            
        data.append([country, speed, hour, vpn, device, 1 if is_attacker else 0])
        
    df = pd.DataFrame(data, columns=['Geo', 'Speed', 'Hour', 'VPN', 'Device', 'Label'])
    df['Geo_Code'] = le.transform(df['Geo'])
    
    model = RandomForestClassifier(n_estimators=50)
    model.fit(df[['Geo_Code', 'Speed', 'Hour', 'VPN', 'Device']], df['Label'])
    
    return model, le

ai_model, le_country = train_ai_model()

def get_ip_details_api(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if r['status'] == 'success':
            return r['country'], r['isp']
        return "Unknown", "Unknown"
    except:
        return "Unknown", "Unknown"

def hybrid_analysis_engine(ip_input, device_str, vpn_bool, hour, speed):
    # 1. CHECK RATE LIMIT FIRST
    if check_rate_limit(ip_input):
        return "🚫 BLOCKED: DDoS / Brute Force Detected (Rate Limit Exceeded)", None, None
    
    # 2. LIVE CLOUD API
    real_country, isp = get_ip_details_api(ip_input)
    
    # 3. AI PREDICTION (Global Safety Net)
    try:
        if real_country not in le_country.classes_:
            geo_code = le_country.transform(['Unknown'])[0]
        else:
            geo_code = le_country.transform([real_country])[0]
    except:
        geo_code = le_country.transform(['Unknown'])[0]
        
    device_val = 1 if device_str == 'Trusted' else 0
    vpn_val = 1 if vpn_bool else 0
    
    ai_prob = ai_model.predict_proba([[geo_code, speed, hour, vpn_val, device_val]])[0][1]
    ai_conf = round(ai_prob * 100, 1)
    
    # 4. LOGIC & DECISION
    score = 0
    reasons = []
    
    if real_country in ['China', 'Russia', 'Iran', 'North Korea', 'Syria']: 
        score += 5
        reasons.append(f"Geo-Block High Risk ({real_country})")
        
    if speed > 100 or speed < 30: 
        score += 2
        reasons.append(f"Biometric Speed Anomaly ({speed} WPM)")
        
    if ai_conf > 70: 
        score += 3
        reasons.append(f"AI Detected Anomaly ({ai_conf}%)")
    
    if score >= 4: verdict = "🚫 BLOCK ACCESS"
    elif score >= 2: verdict = "⚠️ VERIFY (OTP)"
    else: verdict = "✅ ALLOW"
    
    # 5. LOG TO DATABASE
    log_to_db(ip_input, real_country, score, verdict)
    
    # 6. GENERATE PDF
    report_text = f"Decision: {verdict}\nLocation: {real_country}\nISP: {isp}\nRisk Score: {score}/10\n\nFactors:\n" + "\n".join(reasons)
    pdf_file = generate_pdf_report(ip_input, real_country, verdict, report_text)
    
    # 7. CHART (Fixed for Cloud)
    fig = plt.figure(figsize=(4,4))
    categories = ['Geo', 'Time', 'Speed', 'VPN', 'Device']
    values = [
        1.0 if real_country in ['China', 'Russia', 'Iran'] else 0.2,
        1.0 if hour < 6 else 0.2,
        1.0 if speed > 100 else 0.2,
        1.0 if vpn_bool else 0.2,
        1.0 if device_val==0 else 0.2
    ]
    values += values[:1]
    angles = np.linspace(0, 2*np.pi, len(categories), endpoint=False).tolist() + [0]
    
    ax = plt.subplot(111, polar=True)
    ax.fill(angles, values, color='red' if 'BLOCK' in verdict else 'green', alpha=0.3)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories)
    ax.set_yticklabels([])
    ax.set_title("Attack Vector")
    
    return report_text, fig, pdf_file

# ==========================================
# 4. DASHBOARD UI
# ==========================================
with gr.Blocks(theme=gr.themes.Soft()) as dashboard:
    gr.Markdown("# 🛡️ Global Adaptive Security Suite")
    
    with gr.Tab("🔑 Crypto Login"):
        gr.Markdown("### Zero-Knowledge Authentication")
        user_id = gr.Textbox(label="User ID", value="admin@corp")
        chk_hack = gr.Checkbox(label="Simulate Hacker?")
        btn_cryp = gr.Button("Secure Login", variant="primary")
        out_log = gr.Textbox(label="Logs", lines=6)
        out_stat = gr.Label()
        btn_cryp.click(simulate_crypto_auth, [user_id, chk_hack], [out_log, out_stat])

    with gr.Tab("☁️ Cloud Scanner & PDF"):
        gr.Markdown("### Live Adaptive Security Engine (Global)")
        with gr.Row():
            in_ip = gr.Textbox(label="IP Address (Try 8.8.8.8 or 185.174.100.1)", value="8.8.8.8")
            in_dev = gr.Radio(['Trusted', 'Unknown'], label="Device", value="Trusted")
            in_vpn = gr.Checkbox(label="VPN?", value=False)
            in_hr = gr.Slider(0, 23, label="Hour", value=14)
            in_spd = gr.Slider(0, 150, label="Speed", value=60)
            btn_scan = gr.Button("Analyze Risk 🚀")
        with gr.Row():
            out_rep = gr.Textbox(label="Report")
            out_plot = gr.Plot()
        out_pdf = gr.File(label="Download Forensic Report 📄")
        btn_scan.click(hybrid_analysis_engine, [in_ip, in_dev, in_vpn, in_hr, in_spd], [out_rep, out_plot, out_pdf])

    with gr.Tab("👮 Admin Console (Database)"):
        gr.Markdown("### 🗄️ Immutable Security Logs (SQLite)")
        gr.Markdown("This table records every attack for compliance auditing.")
        btn_refresh = gr.Button("Refresh Logs 🔄")
        out_db = gr.Dataframe(label="Attack History")
        btn_refresh.click(fetch_all_logs, outputs=out_db)

# --- CRITICAL CLOUD RUN CONFIGURATION ---
if __name__ == "__main__":
    # Get the PORT environment variable (default to 7860 if local)
    # Cloud Run REQUIRES us to listen on '0.0.0.0' and the specific PORT it provides.
    port = int(os.environ.get("PORT", 7860))
    dashboard.launch(server_name="0.0.0.0", server_port=port)
