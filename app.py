from flask import Flask, render_template, request, jsonify, Response
import whois
import datetime
import os
import pickle
import numpy as np
import pefile
import sqlite3
import tldextract
import requests
import logging
import zipfile
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import dns.resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import hashlib
import joblib



# ======================================================
# 1. INITIAL SETUP & LOGGING
# ======================================================
logging.basicConfig(
    filename='security_audit.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

app = Flask(__name__)
limiter = Limiter(
    lambda: "fixed-key",
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ======================================================
# 2. DATABASE SETUP
# ======================================================
def init_db():
    conn = sqlite3.connect('scans.db')
    cursor = conn.cursor()
    
    # 1. URL History Table 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            established_on TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 2. FILE History Table 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            result TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()
def save_to_db(url, result, est_date):
    try:
        conn = sqlite3.connect('scans.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scan_history (url, result, established_on) VALUES (?, ?, ?)", 
                       (url, result, est_date))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Database Error: {e}")
        
        
def save_file_to_db(filename, file_hash, result):
    try:
        conn = sqlite3.connect('scans.db')
        cursor = conn.cursor()
        # file_history table 
        cursor.execute("INSERT INTO file_history (filename, file_hash, result) VALUES (?, ?, ?)", 
                       (filename, file_hash, result))
        conn.commit()
        conn.close()
        print(f"File {filename} successfully saved to DB") # Debugging ke liye
    except Exception as e:
        print(f"Database Error (File): {e}")        



# ======================================================
# 3. MALWARE MODEL & UNZIP LOGIC (Updated for CyberCop)
# ======================================================
file_model = None
model_features = None

def extract_model():
    zip_path = 'model.zip'
    model_path = 'malware_model.pkl'
    if not os.path.exists(model_path) and os.path.exists(zip_path):
        print("📦 Unzipping model file...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall('.')
        print("✅ Model unzipped successfully!")

def load_file_model():
    global file_model, model_features
    extract_model()
    try:
        # Dono files load karna zaruri hai taaki feature order sahi rahe
        if os.path.exists('malware_model.pkl') and os.path.exists('model_features.pkl'):
            file_model = joblib.load('malware_model.pkl')
            model_features = joblib.load('model_features.pkl')
            print("✅ SUCCESS: CyberCop AI Brain Loaded!")
            return True
        else:
            print("❌ Model files missing!")
            return False
    except Exception as e:
        print(f"❌ Error loading model: {e}")
        return False

# Model load karna shuruat mein hi
load_file_model()

def extract_pe_features(file_path):
    try:
        pe = pefile.PE(file_path)
        
        # Naye Dataset ke hisab se features nikalna
        # Note: Ye exactly wahi order hona chahiye jo model_features.pkl mein hai
        raw_features = {
            'Machine': pe.FILE_HEADER.Machine,
            'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
            'Characteristics': pe.FILE_HEADER.Characteristics,
            'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
            'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
            'SectionMaxEntropy': max([s.get_entropy() for s in pe.sections]) if pe.sections else 0
        }
        
        # Sahi order mein list banana
        features = [raw_features[f] for f in model_features]
        
        pe.close()
        return np.array(features).reshape(1, -1)
    except Exception as e:
        print(f"⚠️ Forensic Extraction Error: {e}")
        return None

def signature_scan(file_path):
    # Zyada common patterns add kiye hain
    malicious_signatures = ["EICAR", "GetRemoteProcAddress", "VirtualAllocEx", "WriteProcessMemory", "ShellExecute", "CreateRemoteThread"] 
    try:
        with open(file_path, "rb") as f:
            # Pura file read karne ke bajaye chunks mein read karna fast hota hai
            content = f.read(1024 * 1024).decode(errors='ignore') # Pehla 1MB scan karein
            for sig in malicious_signatures:
                if sig in content:
                    return True, f"Found {sig} (Malicious Pattern)"
        return False, "No known signature"
    except Exception as e:
        return False, f"Scan Error: {str(e)}"
# ======================================================
# 4. PHISHING SCANNER LOGIC
# ======================================================
def check_url_live(url):
    try:
        ext = tldextract.extract(url)
        hostname = f"{ext.domain}.{ext.suffix}"
        est_on, age_days = "N/A", "N/A"
        
        try:
            domain_info = whois.whois(hostname)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            if creation_date:
                now = datetime.datetime.now()
                if creation_date.tzinfo is not None: creation_date = creation_date.replace(tzinfo=None)
                est_on = creation_date.strftime('%d %B, %Y')
                age_days = (now - creation_date).days
        except:
            est_on = "Hidden/Private"

        trusted_brands = ['facebook', 'google', 'instagram', 'hdfc', 'sbi', 'amazon']
        for brand in trusted_brands:
            if brand in url.lower() and brand not in hostname.lower():
                return f"🚨 DANGER: Spoofing Attack! Pretending to be {brand.capitalize()}.", est_on, age_days

        if isinstance(age_days, int) and age_days < 90:
            return f"🚨 DANGER: New Domain ({age_days} days old). Potential Phishing!", est_on, age_days

        if est_on == "Hidden/Private":
            return "🚨 WARNING: Ownership Metadata is hidden. High risk site.", est_on, age_days

        return "✅ SAFE: Verified Legacy Domain.", est_on, age_days
    except Exception as e:
        return f"🚨 SYSTEM ERROR: {str(e)}", "Error", "N/A"

# ======================================================
# 5. DEEP ANALYSIS ENGINE (Fixed Indentation & Variables)
# ======================================================
def deep_analyze_url(url):
    # Variables initialize karein taaki N/A na dikhe
    results = {
    'url': url,
    'domain_exists': False,
    'structural_risk': 0,
    'structural_desc': "Clean structure.",
    'domain_age': "Unknown",
    'domain_check_desc': "",
    'is_blacklisted': False,
    'final_score': 100,
    'ai_summary': "Analyzing...",
    'domain_info_status': "Safe",
    'established_on': "N/A",
    'domain_type_desc': "N/A",  # Ise initialize hona zaruri hai
    'domain_metadata': "N/A"    # Ise bhi initialize hona zaruri hai
}

    # 1. Structural Scan (Aapka logic)
    dots = url.count('.')
    if dots > 3 or "@" in url or "-" in url:
        results['structural_risk'] = 1
        results['structural_desc'] = f"Suspicious! URL has {dots} dots and symbols."
        results['final_score'] -= 30

    # 2. Domain Existence (DNS) & WHOIS (Aapka logic)
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
        dns.resolver.resolve(domain, 'A')
        results['domain_exists'] = True
        
        # Connect to your check_url_live logic
        msg, est_date, age = check_url_live(url)
        results['established_on'] = est_date
        results['domain_age'] = age
        results['domain_info_status'] = msg
    except:
        results['domain_exists'] = False
        results['final_score'] = 0
        results['ai_summary'] = "STOP! Ghost domain detected in DNS records."
        save_to_db(url, "FAKE/NOT FOUND", "N/A")
        return results

    # 3. AI Intent (Scraping) - FIXED for Restricted Errors
    try:
        # User-Agent headers added to bypass blocks
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        # SSL Verification ko bypass karne ke liye verify=False add kiya (sirf metadata ke liye safe hai)
        response = requests.get(url, timeout=10, headers=headers, verify=True)
        
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            title_tag = soup.title.string if soup.title else "No Title Found"
            
            # Type detection logic
            if any(word in title_tag.lower() for word in ['login', 'account', 'sign']):
                results['domain_type_desc'] = "Authentication Portal"
            else:
                results['domain_type_desc'] = "General Website"

            # Metadata update
            server = response.headers.get('Server', 'Protected')
            results['domain_metadata'] = f"Server: {server} | Title: {title_tag[:30]}"
            results['ai_summary'] = "Site identity verified through deep content analysis."
        else:
            # Agar abhi bhi Restricted aaye toh default values set karein
            results['domain_type_desc'] = f"Restricted Content ({response.status_code})"
            results['domain_metadata'] = "Metadata locked by site firewall."
            results['ai_summary'] = "Site reachable but deep metadata extraction was denied."
            
    except Exception as e:
        results['domain_type_desc'] = "Unidentified"
        results['domain_metadata'] = "Connection failed."

    # 4. Final Database Save (Pura hone ke baad hi save)
    res_text = "SAFE" if results['final_score'] > 70 else "SUSPICIOUS"
    save_to_db(url, res_text, results['established_on'])
    
    return results
# ======================================================
# 6. FLASK ROUTES
# ======================================================
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan_url', methods=['POST'])
@limiter.limit("5 per minute")
def scan_route():
    target_url = request.form.get('url')
    if not target_url:
        return "Please enter a URL", 400
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
        
    analysis_data = deep_analyze_url(target_url)
    return render_template('result.html', **analysis_data)
#=====================================================
@app.route('/scan_file', methods=['POST'])
@limiter.limit("5 per minute")

def scan_file():
    if 'file' not in request.files: return "No file uploaded", 400
    file = request.files['file']
    
    # 1. File save logic
    upload_dir = os.path.join('static', 'uploads')
    if not os.path.exists(upload_dir): os.makedirs(upload_dir)
    file_path = os.path.join(upload_dir, file.filename)
    file.save(file_path)
    
    # 2. GENERATE MD5 HASH (Ye line missing hogi)
    with open(file_path, "rb") as f:
        file_md5 = hashlib.md5(f.read()).hexdigest()

    # 3. Default Values 
    file_data = {
        'filename': file.filename,
        'size': f"{os.path.getsize(file_path) / 1024:.2f} KB",
        'extension': file.filename.split('.')[-1].upper(),
        'scan_result': "✅ SAFE: No Threats Found", # Default status
        'prediction_score': "Low Risk",
        'pe_details': "Standard File Structure"
    }
    
    # 4. Pehle Signature Scan (EICAR check)
    is_malicious, sig_msg = signature_scan(file_path)
    
    if is_malicious:
        file_data['scan_result'] = "🚨 DANGEROUS: Malware Detected!"
        file_data['prediction_score'] = "100% Risk (Signature Match)"
        file_data['pe_details'] = f"Malicious pattern found: {sig_msg}"
        
    # 5. Agar signature nahi mila, toh AI se pucho
    elif file.filename.lower().endswith(('.exe', '.dll')):
        features = extract_pe_features(file_path)
        if features is not None and file_model is not None:
            prediction = file_model.predict(features)[0]
            
            if prediction == 1:
                file_data['scan_result'] = "⚠️ SUSPICIOUS: Behavioral Anomaly"
                file_data['prediction_score'] = "High Risk (AI Prediction)"
                file_data['pe_details'] = "Abnormal PE Header structure detected by Machine Learning."

    # 6. Cleanup
    if os.path.exists(file_path): os.remove(file_path)
    
    save_file_to_db(file_data['filename'], file_md5, file_data['scan_result'])
    
    return render_template('file_result.html', file_md5=file_md5, **file_data)
#=====================================================
@app.route('/history')
def history():
    try:
        
        with sqlite3.connect('scans.db') as conn:
            cursor = conn.cursor()
            
            # 1. URL Data fetch karein
            cursor.execute("SELECT * FROM scan_history ORDER BY timestamp DESC")
            urls = cursor.fetchall()
            
            # 2. File Data fetch karein 
            cursor.execute("SELECT * FROM file_history ORDER BY timestamp DESC")
            files = cursor.fetchall()
            
        return render_template('history.html', urls=urls, files=files)
    except Exception as e:
        print(f"Database Error: {e}")
        return "Database Connection Failed. Please check scans.db"
# ======================================================
   
@app.route('/clear_history', methods=['POST'])
def clear_history():
    try:
        # 'with' use karne se connection automatically handle aur close hota hai
        with sqlite3.connect('scans.db') as conn:
            cursor = conn.cursor()
            # Dono tables ko saaf karein
            cursor.execute("DELETE FROM scan_history")
            cursor.execute("DELETE FROM file_history")
            conn.commit()
        return jsonify({"status": "success", "message": "All history wiped successfully!"})
    except Exception as e:
        print(f"Wipe Error: {e}")
        return jsonify({"status": "error", "message": "Database is busy or connection failed."}), 500    

# ======================================================
# 6. SECURITY MONITORING & RUN (FIXED SPACING)
# ======================================================
@app.before_request
def monitor_activity():
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    payload = str(request.form.to_dict()) + str(request.args.to_dict())
    suspicious_patterns = ['<script>', 'alert(', 'OR 1=1', 'union select']
    
    for pattern in suspicious_patterns:
        if pattern in payload.lower():
            logging.warning(f"⚠️ ATTACK FROM {client_ip} | Path: {request.path} | Pattern: {pattern}")
            return # Block locally or just log

    logging.info(f"User IP: {client_ip} | Accessed: {request.path}")

if __name__ == "__main__":
    # Ye dono lines 'if' ke andar properly indented hain
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)