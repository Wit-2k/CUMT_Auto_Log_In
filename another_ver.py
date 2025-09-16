import requests
import socket
import time
import re
import json
from getmac import get_mac_address

# --- 1. 配置你的个人信息 ---
my_username = "23223976"  # 改成你的学号
my_password = "cumt-3976"  # 改成你的明文密码
operator_suffix = "@telecom"
full_user_account = f"{my_username}{operator_suffix}"


# --- 2. 自动获取本机IP和MAC地址 ---
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.2.5.251", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = None
    finally:
        s.close()
    return ip


def get_local_mac():
    try:
        mac = get_mac_address()
        if mac:
            return mac.replace(":", "").replace("-", "").lower()
    except Exception:
        return None


print("正在本地获取网络信息...")
user_ip = get_local_ip()
user_mac = get_local_mac()

if not user_ip or not user_mac:
    print("❌ 无法获取本机IP或MAC地址。")
    exit()

print(f"  - 成功获取本机IP: {user_ip}")
print(f"  - 成功获取本机MAC: {user_mac}")


# --- 3. 构造并发送GET登录请求 ---

login_base_url = "http://10.2.5.251:801/eportal/"
timestamp = int(time.time() * 1000)

login_params = {
    "c": "Portal",
    "a": "login",
    "callback": f"dr{timestamp}",
    "login_method": "1",
    "user_account": full_user_account,
    "user_password": my_password,
    "wlan_user_ip": user_ip,
    "wlan_user_mac": user_mac,
    "wlan_ac_ip": "10.2.4.1",
    "wlan_ac_name": "NAS",
    "jsVersion": "3.0",
    "_": timestamp,
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
}

print("\n正在发送登录认证请求...")
try:
    login_response = requests.get(
        login_base_url, params=login_params, headers=headers, timeout=5
    )

    login_response.encoding = "utf-8"

    jsonp_text = login_response.text
    try:
        json_str = re.search(r"\((.*)\)", jsonp_text).group(1)
        result = json.loads(json_str)
        message = result.get("msg", "")

        if "认证成功" in message or result.get("result") == "1":
            print(f"✅ 登录成功！服务器消息: {message}")
        else:
            print(f"❌ 登录失败！服务器消息: {message}")
            if "密码错误" in message:
                print("   请检查你的密码。")
            if "username is error" in message:
                print("   请检查学号和运营商后缀(@telecom)是否正确。")

    except (AttributeError, json.JSONDecodeError):
        print("❌ 解析返回数据失败。")
        print("   原始返回内容:", jsonp_text)

except requests.exceptions.RequestException as e:
    print(f"❌ 登录请求失败。错误: {e}")
