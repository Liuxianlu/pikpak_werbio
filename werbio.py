# 原作者：B站纸鸢的花语
# 二改作者：非雨  https://github.com/liuxianlu
# 1.增加3个api邮箱接口
# 2.增加卡密验证、可直接部署在网页运行
# bug: 运行两个小时后会出现add_days异常失败，部署在宝塔面板的可设置为定时重启项目即可解决！

# 声明：纸鸢花的花语所提供的任何资源或素材代码，仅供学习交流 和技术分析，严禁用于任何商业牟利行为(包括但不限于引流用户加入社群，利用免费学习素材牟利贩卖，冒充原作者盗用引流增加用户数…)
# 出现任何后果自行承担，与资源的分享者没有任何关系和责任，如出现违反规定侵权行为，原作者有权对违规者进行版权控诉处理。

# 如何运行：
# 运行后提示什么错误就安装什么库 例如: pip install requests
# 运行成功后复制网址到浏览器打开，即可运行在网页执行邀请程序，可搭建部署在服务器运行
# 接口卡密1，2，3 替换为实际购买的邮箱卡密 邮箱购买地址 https://shanyouxiang.com/    https://zhanghaoya.com/       https://atufn.com/


import poplib
import hashlib
import json
import random
import re
import time
import requests
import uuid
import email

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ThreadPoolExecutor
from pywebio.input import input_group, input, TEXT
from pywebio.output import put_text, put_markdown, clear, put_html
from pywebio import start_server
from datetime import datetime


def wxpusher(new_email, password, invitation_code):
    global randint_ip
    app_token = ""
    if app_token:
        api_url = "https://wxpusher.zjiecode.com/api/send/message"
        data = {
            "appToken": app_token,
            "summary": "邀请成功: " + invitation_code,
            "content": "<h1>PikPak运行结果通知🔔</h1><br/><h3>邀请码：" + invitation_code + "</h3><h4>账户：" + new_email + "</h4><h4>密码：" + password + "</h4>",
            "contentType": 2,
            "topicIds": [30126],
            "uids": [],
            "verifyPayType": 0
        }
        headers = {
            # X-Forwarded-For': str(randint_ip)
        }
        json_data = json.dumps(data)
        headers = {'Content-Type': 'application/json'}
        response = requests.post(api_url, headers=headers, data=json_data)
        data = response.json()
    # print(f'wxpusher推送结果：{data["msg"]}')


# API邮箱接口
# 接口1
key1 = "接口卡密1"
def check_balance1():
    url = f'https://zizhu.shanyouxiang.com/yue?card={key1}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data.get('num', None)
        else:
            print(f"请求失败，状态码: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"请求出错: {e}")
        return None


def get_kucun():
    response = requests.get("http://zizhu.shanyouxiang.com/kucun")
    if response.status_code == 200:
        data = json.loads(response.text)
        if int(data["hotmail"]) > 0:
            return "hotmail"
        elif int(data["outlook"]) > 0:
            return "outlook"
        else:
            # print("接口1没有邮箱, 库存为空，等待补货")
            return None
    else:
        print(
            f"Failed to fetch data. HTTP Status Code: {response.status_code}")
        return None


def get_account_and_password(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.text.strip()
            accounts = data.split('\n')
            account_dict = {}
            for account in accounts:
                if '----' in account:
                    email, password = account.split('----')
                    account_dict[email.strip()] = password.strip()
            return account_dict
        else:
            print(
                f"Failed to fetch data. HTTP Status Code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def get_third_email():
    res = check_balance1()
    print("接口1:", res)
    if res is None:
        print("闪邮箱卡密余额不足")
        return None

    res = get_kucun()
    if res is None:
        return None

    if res == "outlook":
        url = f"http://zizhu.shanyouxiang.com/huoqu?shuliang=1&leixing=outlook&card={key1}"
        account_info = get_account_and_password(url)
        if account_info:
            email_user, email_pass = list(account_info.items())[0]
            return email_user, email_pass
    if res == "hotmail":
        url = f"http://zizhu.shanyouxiang.com/huoqu?shuliang=1&leixing=hotmail&card={key1}"
        account_info = get_account_and_password(url)
        if account_info:
            email_user, email_pass = list(account_info.items())[0]
            return email_user, email_pass


# 接口2
key2 = "接口卡密2"
def check_balance2():
    url = f'https://zhanghaoya.com/store/ga/balance?key={key2}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data.get('Data', None)
        else:
            print(f"请求失败，状态码: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"请求出错: {e}")
        return None


def get_account_and_password2(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data["Code"] == 200:
                account_info = data["Data"].replace("<br>", "").strip()
                return account_info
            else:
                print(f"API returned an error: {data['Message']}")
                return None
        else:
            print(
                f"Failed to fetch data. HTTP Status Code: {response.status_code}")
            return None
    except requests.Timeout:
        print("Request timed out.")
        return None
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None


def get_third_email2():
    res = check_balance2()
    print("接口2:", res)
    if res is None:
        print("zhanghaoya卡密余额不足")
        return None

    url = f"https://zhanghaoya.com/store/ga/account?type=hotmail&quantity=1&key={key2}"
    url1 = f"https://zhanghaoya.com/store/ga/account?type=outlook&quantity=1&key={key2}"

    account_info = get_account_and_password2(url)
    if account_info:
        email_user, email_pass = account_info.split(':')
        return email_user, email_pass

    account_info = get_account_and_password2(url1)
    if account_info:
        email_user, email_pass = account_info.split(':')
        return email_user, email_pass

    return None


# 接口3
key3 = '接口卡密3'
def check_balance3():
    url = f'http://api.atufn.com/yue?card={key3}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data.get('balance', None)
        else:
            print(f"请求失败，状态码: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"请求出错: {e}")
        return None


def get_kucun3():
    response = requests.get("http://api.atufn.com/kucun")
    if response.status_code == 200:
        data = json.loads(response.text)
        if int(data["hotmail"]) > 0:
            return "hotmail"
        elif int(data["outlook"]) > 0:
            return "outlook"
        else:
            # print("接口3没有邮箱, 库存为空，等待补货")
            return None
    else:
        print(
            f"Failed to fetch data. HTTP Status Code: {response.status_code}")
        return None


def get_account_and_password3(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.text.strip()
            accounts = data.split('\n')
            account_dict = {}
            for account in accounts:
                if '----' in account:
                    email, password = account.split('----')
                    account_dict[email.strip()] = password.strip()
            return account_dict
        else:
            print(
                f"Failed to fetch data. HTTP Status Code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def get_third_email3():
    res = check_balance3()
    print("接口3:", res)
    if res is None:
        print("atufn卡密余额不足")
        return None
    res = get_kucun3()
    if res is None:
        return None
    if res == "outlook":
        url = f"http://api.atufn.com/huoqu?shuliang=1&leixing=outlook&card={key3}"
        account_info = get_account_and_password3(url)
        if account_info:
            email_user, email_pass = list(account_info.items())[0]
            return email_user, email_pass
    if res == "hotmail":
        url = f"http://api.atufn.com/huoqu?shuliang=1&leixing=hotmail&card={key3}"
        account_info = get_account_and_password3(url)
        if account_info:
            email_user, email_pass = list(account_info.items())[0]
            return email_user, email_pass


def process_email(raw_email, email_id, mail):
    email_message = email.message_from_bytes(raw_email)
    if email_message.is_multipart():
        for part in email_message.walk():
            if part.get_content_type() == 'text/plain' and not part.get('Content-Disposition'):
                body = part.get_payload(decode=True)
                body_text = body.decode('utf-8')
                match = re.search(r'\d{6}', body_text)
                if match:
                    code = match.group()
                    print(f'获取到验证码: {code}')
                    return code
    else:
        body = email_message.get_payload(decode=True)
        body_text = body.decode('utf-8')
        match = re.search(r'\d{6}', body_text)
        if match:
            code = match.group()
            print(f'获取到验证码: {code}')
            return code

    print("邮件正文为空或无法解码")
    return None


def get_email_with_third_party(recipient_email, email_user, email_pass, delay=2, max_retries=40):
    pop3_server = "pop-mail.outlook.com"
    sender_email = 'noreply@accounts.mypikpak.com'
    retries = 0

    while retries < max_retries:
        try:
            mail = poplib.POP3_SSL(pop3_server)
            mail.user(email_user)
            mail.pass_(email_pass)
            num_messages = len(mail.list()[1])

            for i in range(num_messages):
                response, lines, octets = mail.retr(i + 1)
                raw_email = b'\n'.join(lines)
                code = process_email(raw_email, i + 1, mail)
                if code:
                    return code

            mail.quit()
        except Exception as e:
            print(f"发生错误: {e}")

        retries += 1
        time.sleep(delay)

    return None


# 动态代理
def get_proxy():
    proxies = {}
    return proxies


def get_randint_ip():
    m = random.randint(0, 255)
    n = random.randint(0, 255)
    x = random.randint(0, 255)
    y = random.randint(0, 255)
    randomIP = str(m) + '.' + str(n) + '.' + str(x) + '.' + str(y)
    return randomIP


randint_ip = get_randint_ip()


# 加密算法
def r(e, t):
    n = t - 1
    if n < 0:
        n = 0
    r = e[n]
    u = r["row"] // 2 + 1
    c = r["column"] // 2 + 1
    f = r["matrix"][u][c]
    l = t + 1
    if l >= len(e):
        l = t
    d = e[l]
    p = l % d["row"]
    h = l % d["column"]
    g = d["matrix"][p][h]
    y = e[t]
    m = 3 % y["row"]
    v = 7 % y["column"]
    w = y["matrix"][m][v]
    b = i(f) + o(w)
    x = i(w) - o(f)
    return [s(a(i(f), o(f))), s(a(i(g), o(g))), s(a(i(w), o(w))), s(a(b, x))]


def i(e):
    return int(e.split(",")[0])


def o(e):
    return int(e.split(",")[1])


def a(e, t):
    return str(e) + "^⁣^" + str(t)


def s(e):
    t = 0
    n = len(e)
    for r in range(n):
        t = u(31 * t + ord(e[r]))
    return t


def u(e):
    t = -2147483648
    n = 2147483647
    if e > n:
        return t + (e - n) % (n - t + 1) - 1
    if e < t:
        return n - (t - e) % (n - t + 1) + 1
    return e


def c(e, t):
    return s(e + "⁣" + str(t))


def img_jj(e, t, n):
    return {"ca": r(e, t), "f": c(n, t)}


def uuid():
    return ''.join([random.choice('0123456789abcdef') for _ in range(32)])


def md5(input_string):
    return hashlib.md5(input_string.encode()).hexdigest()


def get_sign(xid, t):
    e = [
        {"alg": "md5", "salt": "KHBJ07an7ROXDoK7Db"},
        {"alg": "md5", "salt": "G6n399rSWkl7WcQmw5rpQInurc1DkLmLJqE"},
        {"alg": "md5", "salt": "JZD1A3M4x+jBFN62hkr7VDhkkZxb9g3rWqRZqFAAb"},
        {"alg": "md5", "salt": "fQnw/AmSlbbI91Ik15gpddGgyU7U"},
        {"alg": "md5", "salt": "/Dv9JdPYSj3sHiWjouR95NTQff"},
        {"alg": "md5", "salt": "yGx2zuTjbWENZqecNI+edrQgqmZKP"},
        {"alg": "md5", "salt": "ljrbSzdHLwbqcRn"},
        {"alg": "md5", "salt": "lSHAsqCkGDGxQqqwrVu"},
        {"alg": "md5", "salt": "TsWXI81fD1"},
        {"alg": "md5", "salt": "vk7hBjawK/rOSrSWajtbMk95nfgf3"}
    ]
    md5_hash = f"YvtoWO6GNHiuCl7xundefinedmypikpak.com{xid}{t}"
    for item in e:
        md5_hash += item["salt"]
        md5_hash = md5(md5_hash)
    return md5_hash


# 初始安全验证
def init(xid, mail):
    global randint_ip
    url = 'https://user.mypikpak.com/v1/shield/captcha/init'
    body = {
        "client_id": "YvtoWO6GNHiuCl7x",
        "action": "POST:/v1/auth/verification",
        "device_id": xid,
        "captcha_token": "",
        "meta": {
            "email": mail
        }
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0',
        'X-Forwarded-For': str(randint_ip)
    }
    retries = 0
    max_retries = 3
    while retries < max_retries:
        try:
            response = requests.post(
                url, json=body, headers=headers, timeout=5)
            response_data = response.json()
            print('初始安全验证')
            return response_data
        except:
            retries += 1

# 获取token
def get_new_token(xid, captcha):
    retries = 0
    max_retries = 3
    while retries < max_retries:
        try:
            response2 = requests.get(
                f"https://user.mypikpak.com/credit/v1/report?deviceid={xid}&captcha_token={captcha}&type"
                f"=pzzlSlider&result=0", proxies=get_proxy(), timeout=5)

            response_data = response2.json()
            # print('获取验证TOKEN中......')
            return response_data
        except:
            retries += 1

# 发送验证码
def verification(captcha_token, xid, mail):
    global randint_ip
    url = 'https://user.mypikpak.com/v1/auth/verification'
    body = {
        "email": mail,
        "target": "ANY",
        "usage": "REGISTER",
        "locale": "zh-CN",
        "client_id": "YvtoWO6GNHiuCl7x"
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-captcha-token': captcha_token,
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
        # 'X-Forwarded-For': str(randint_ip)
    }

    retries = 0
    max_retries = 2
    while retries < max_retries:
        try:
            response = requests.post(
                url, json=body, headers=headers, timeout=5)
            response_data = response.json()
            print('发送验证码')
            return response_data
        except:
            retries += 1


# 验证码结果
def verify(xid, verification_id, code):
    global randint_ip
    url = 'https://user.mypikpak.com/v1/auth/verification/verify'
    body = {
        "verification_id": verification_id,
        "verification_code": code,
        "client_id": "YvtoWO6GNHiuCl7x"
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
        # 'X-Forwarded-For': str(randint_ip)
    }
    retries = 0
    max_retries = 2
    while retries < max_retries:
        try:
            response = requests.post(
                url, json=body, headers=headers, timeout=5)
            response_data = response.json()
            print('验证码验证结果')
            return response_data
        except:
            retries += 1


# 验证注册结果
def signup(xid, mail, code, verification_token):
    global randint_ip
    url = 'https://user.mypikpak.com/v1/auth/signup'
    body = {
        "email": mail,
        "verification_code": code,
        "verification_token": verification_token,
        'name': f'qihang{random.randint(1, 1000000000)}vip',
        "password": "qwe103",
        "client_id": "YvtoWO6GNHiuCl7x"
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'accept-language': 'zh-CN',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
        # 'X-Forwarded-For': str(randint_ip)
    }
    retries = 0
    max_retries = 2
    while retries < max_retries:
        try:
            response = requests.post(
                url, json=body, headers=headers, timeout=5)
            response_data = response.json()
            print('验证注册结果')
            return response_data
        except:
            retries += 1


# 二次安全验证
def init1(xid, access_token, sub, sign, t):
    global randint_ip
    url = 'https://user.mypikpak.com/v1/shield/captcha/init'
    body = {
        "client_id": "YvtoWO6GNHiuCl7x",
        "action": "POST:/vip/v1/activity/invite",
        "device_id": xid,
        "captcha_token": access_token,
        "meta": {
            "captcha_sign": "1." + sign,
            "client_version": "undefined",
            "package_name": "mypikpak.com",
            "user_id": sub,
            "timestamp": t
        },
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
        # 'X-Forwarded-For': str(randint_ip)
    }
    retries = 0
    max_retries = 2
    while retries < max_retries:
        try:
            response = requests.post(
                url, json=body, headers=headers, timeout=5)
            response_data = response.json()
            print('通过二次安全验证')
            return response_data
        except:
            retries += 1


# 确认邀请
def invite(access_token, captcha_token, xid):
    global randint_ip
    url = 'https://api-drive.mypikpak.com/vip/v1/activity/invite'
    body = {
        "apk_extra": {
            "invite_code": ""
        }
    }
    headers = {
        'host': 'api-drive.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'authorization': 'Bearer ' + access_token,
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) PikPak/2.3.2.4101 '
                      'Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-captcha-token': captcha_token,
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-system-language': 'zh-CN'
        # 'X-Forwarded-For': str(randint_ip)
    }
    retries = 0
    max_retries = 2
    while retries < max_retries:
        try:
            response = requests.post(
                url, json=body, headers=headers, timeout=5)
            response_data = response.json()
            print('确认邀请')
            return response_data
        except:
            retries += 1


# 三次安全验证
def init2(xid, access_token, sub, sign, t):
    global randint_ip
    url = 'https://user.mypikpak.com/v1/shield/captcha/init'
    body = {
        "client_id": "YvtoWO6GNHiuCl7x",
        "action": "post:/vip/v1/order/activation-code",
        "device_id": xid,
        "captcha_token": access_token,
        "meta": {
            "captcha_sign": "1." + sign,
            "client_version": "undefined",
            "package_name": "mypikpak.com",
            "user_id": sub,
            "timestamp": t
        },
    }
    headers = {
        'host': 'user.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'MainWindow Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'PikPak/2.3.2.4101 Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-device-model': 'electron%2F18.3.15',
        'x-device-name': 'PC-Electron',
        'x-device-sign': 'wdi10.ce6450a2dc704cd49f0be1c4eca40053xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        'x-net-work-type': 'NONE',
        'x-os-version': 'Win32',
        'x-platform-version': '1',
        'x-protocol-version': '301',
        'x-provider-name': 'NONE',
        'x-sdk-version': '6.0.0'
        # 'X-Forwarded-For': str(randint_ip)
    }
    retries = 0
    max_retries = 2
    while retries < max_retries:
        try:
            response = requests.post(
                url, json=body, headers=headers, timeout=5)
            response_data = response.json()
            print('通过三次安全验证')
            return response_data
        except:
            retries += 1


# 验证邀请码
def activation_code(access_token, captcha, xid, in_code):
    global randint_ip
    url = 'https://api-drive.mypikpak.com/vip/v1/order/activation-code'
    body = {
        "activation_code": in_code,
        "page": "invite"
    }
    headers = {
        'host': 'api-drive.mypikpak.com',
        'content-length': str(len(json.dumps(body))),
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'zh-CN',
        'authorization': 'Bearer ' + access_token,
        'referer': 'https://pc.mypikpak.com',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'cross-site',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) PikPak/2.3.2.4101 '
                      'Chrome/100.0.4896.160 Electron/18.3.15 Safari/537.36',
        'content-type': 'application/json',
        'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="100"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'x-captcha-token': captcha,
        'x-client-id': 'YvtoWO6GNHiuCl7x',
        'x-client-version': '2.3.2.4101',
        'x-device-id': xid,
        'x-system-language': 'zh-CN',
        'X-Forwarded-For': str(randint_ip)
    }
    retries = 0
    max_retries = 2
    while retries < max_retries:
        try:
            response = requests.post(
                url, json=body, headers=headers, timeout=5)
            response_data = response.json()
            print('开始填写邀请码')
            # print(f'邀请结果:  {json.dumps(response_data, indent=4)}')
            return response_data
        except:
            retries += 1


# -------------------------- 卡密 主函数一系列网络请求--------------------------
# 定义卡密和其使用次数
card_keys = {
    "0727-0827-3382SJ2SJ": 10000,
}


invite_success_limit = 1  # 每行邀请码邀请次数
invitation_records = {}  # 记录邀请码提交次数和时间



def generate_captcha_question():
    num1 = random.randint(1, 10)
    num2 = random.randint(1, 10)
    question = f"请回答：{num1} + {num2} = ?"
    answer = num1 + num2
    return question, answer



def main(incode, num_invitations=invite_success_limit):
    now = datetime.now()
    print("当前日期: ", now)
    start_time = time.time()
    success_count = 0

    global invitation_records
    current_time = time.time()

    # 检查邀请码在24小时内的提交次数
    if incode in invitation_records:
        last_submissions = invitation_records[incode]
        last_submissions = [
            t for t in last_submissions if current_time - t < 36000]  # 保留10小时内的记录
        if len(last_submissions) >= 2:
            result = "24小时已提交2次，请明日再试。"
            return result
        invitation_records[incode] = last_submissions
    else:
        invitation_records[incode] = []

    while success_count < num_invitations:
        try:
            xid = uuid()  # 生成唯一的 xid

            email_info1 = get_third_email()
            if email_info1 is not None:
                email_user, email_pass = email_info1
            else:
                # 尝试第二个接口
                email_info2 = get_third_email2()
                if email_info2 is not None:
                    email_user, email_pass = email_info2
                else:
                    # 尝试第三个接口
                    email_info3 = get_third_email3()
                    if email_info3 is not None:
                        email_user, email_pass = email_info3
                    else:
                        email_user, email_pass = None, None  # 如果所有接口都不行，则设为None

            mail = email_user
            Init = init(xid, mail)
            print(email_user, email_pass)

            captcha_token_info = get_new_token(xid, Init['captcha_token'])
            Verification = verification(
                captcha_token_info['captcha_token'], xid, mail)
            code = get_email_with_third_party(mail, email_user, email_pass)
            verification_response = verify(
                xid, Verification['verification_id'], code)
            signup_response = signup(
                xid, mail, code, verification_response['verification_token'])
            current_time = str(int(time.time()))
            sign = get_sign(xid, current_time)
            init1_response = init1(
                xid, signup_response['access_token'], signup_response['sub'], sign, current_time)
            invite(signup_response['access_token'],
                   init1_response['captcha_token'], xid)
            init2_response = init2(
                xid, signup_response['access_token'], signup_response['sub'], sign, current_time)
            activation = activation_code(
                signup_response['access_token'], init2_response['captcha_token'], xid, incode)
            end_time = time.time()
            run_time = f'{(end_time - start_time):.2f}'


            # 到这里返回是否邀请成功 邀请成功就停止运行 邀请失败就跳出循环 再次执行
           
            try:
                if activation['add_days'] == 5:
                    print(f"邀请成功 邀请码: {incode} email: {mail} 密码：qwe103")
                    result = f"邀请成功: {incode} 运行时间: {run_time}秒<br> 邮箱: {mail} <br> 密码: qwe103"
                    success_count += 1
                    # wxpusher(mail, "qwe103", incode)
                    # 记录提交时间
                    invitation_records[incode].append(time.time())
                    return result
                elif activation['add_days'] == 0:
                    result = f'邀请码: {incode} 邀请失败, 重试...'
                    print(f'邀请码: {incode} 邀请失败, 重试...')
                    return result
                else:
                    if str(e) == "add_days":
                        result = f"异常: {e} 检测邀请码是否有效/程序出错 "
                    else:
                        result = f'异常重试. {e}'
                    return result
            except KeyError as e:
                if str(e) == "'add_days'":
                    result = f"异常: {e} 检测邀请码是否有效/程序出错"
                else:
                    result = f'异常重试.. {e}'
                return result

        except Exception as e:
            # 检查异常信息并设置结果
            if str(e) == "cannot unpack non-iterable NoneType object":
                result = (
                    "异常: 临时邮箱暂没货等待补货 预计1小时恢复"
                )
            elif str(e) == "add_days":
                result = f"异常: {e} 检查邀请码是否有效  程序出错"
            
            elif str(e) == 'captcha_token':
                result = f"异常: {e} 临时邮箱暂没货等待补货 预计1小时恢复"
                
            else:
                if str(e) == "'captcha_token'":
                    result = f"异常: {e} 临时邮箱暂没货等待补货 预计1小时恢复"
                else:
                    result = f'异常重试... {e}'
                
            return result


def web_app():
    put_html('''
        <style>
            .footer {
                display: none !important;
            }
            
            .pywebio_header {
                text-align: center;
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 20px;
            }
            
            .km_title {
                text-align: center;
                color: #495057;
                font-size: 12px;
            }
        </style>
    ''')

    put_html('<script>document.title = "PIKPAK临时会员邀请程序";</script>')
    put_html('<div class="pywebio_header">PIKPAK临时会员邀请程序</div>')
    put_html('<div class="km_title">随用随充次日会员会掉 邀请超50人充不上需要换号 多刷无效<br> 服务器断开/页面卡住解决方法: 复制网址到微信消息里访问</div>')

    form_data = input_group("", [
        input("请输入你的邀请码6-8位数字:", name="incode", type=TEXT,
              required=True, placeholder="打开pikpak我的界面-引荐奖励计划-获取邀请码数字"),
        input("请输入卡密:", name="card_key", type=TEXT,
              required=True, placeholder="请输入卡密")
        # input("邀请次数:", name="numberInvitations", type=NUMBER, value=1, required=True, readonly=True,
        #       placeholder="默认填写1次，不可修改"),
    ])

    incode = form_data['incode']
    card_key = form_data['card_key']
    # numberInvitations = form_data['numberInvitations']

    # 验证卡密
    if card_key not in card_keys or card_keys[card_key] <= 0:
        put_text("卡密无效，联系客服")
        return

    # 更新卡密使用次数
    card_keys[card_key] -= 1

    clear()
    put_html('''
        <style>
            .footer {
                display: none !important;
            }
            .pywebio_header {
                text-align: center;
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 20px;
            }
        </style>
    ''')
    put_html('''
        <div id="countdown" style="text-align: center;">
            正在邀请中...请不要退出页面， <span id="time">30</span> 秒 <br>
            页面倒计时为1秒还未跳转请刷新页面重试一遍
        </div>
        <script>
            var timeLeft = 30;
            var countdownTimer = setInterval(function(){
                if(timeLeft <= 0){
                    clearInterval(countdownTimer);
                   
                    pywebio.output.put_markdown("## 邀请结果");
                } else {
                    document.getElementById("time").innerHTML = timeLeft;
                }
                timeLeft -= 1;
            }, 1000);
        </script>
    ''')

# document.getElementById("countdown").innerHTML = "邀请已结束，稍等...正在处理结果";

    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        # futures = [executor.submit(main, incode) for _ in range(numberInvitations)]
        futures = [executor.submit(main, incode) for _ in range(1)]
        for future in futures:
            result = future.result()
            print(result)
            results.append(result)

    clear()
    put_markdown("## 邀请结果")
    put_html('''
        <style>
            .footer {
                display: none !important;
            }
            .pywebio_header {
                text-align: center;
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 20px;
            }
            .result-container {
                text-align: center;
                font-size: 18px;
                margin-top: 20px;
            }
        </style>
    ''')
    for result in results:
        # put_text(result)
        put_html(f'<div class="result-container">{result}</div>')


if __name__ == '__main__':
    start_server(web_app, host='0.0.0.0', port=8080)