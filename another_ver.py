import requests
import socket
import time
import re
import json
from getmac import get_mac_address

# 引入base64库，用于对加密后的密码进行编码
import base64

# --- 1. 配置你的个人信息 ---
my_username = "23223976"  # 改成你的学号
my_password = "cumt-3976"  # 改成你的明文密码
operator_suffix = "@telecom"
full_user_account = f"{my_username}{operator_suffix}"


# --- 2. 核心：密码加密函数 (模拟JS的XOR加密) ---


def xor_encrypt(text, key):
    """简单的XOR加密函数"""
    lt = len(text)
    lk = len(key)
    result = ""
    for i in range(lt):
        result += chr(ord(text[i]) ^ ord(key[i % lk]))
    return result


def encode_password(password, challenge, token):
    """
    根据eportal的加密逻辑，生成最终的密码字符串。
    这种加密方式非常常见。
    """
    # 构造一个初始的加密字符串
    # hmd5 是一个占位符，实际加密中可能不需要md5，我们先用密码本身
    initial_str = password + token

    # 很多eportal系统会将密码和 challenge 进行xor
    # 并用base64编码，然后加上一个 {xor} 前缀
    encrypted_pass = xor_encrypt(initial_str, challenge)

    # 返回最终格式化的密码
    # 注意：这个逻辑需要根据抓包的JS分析来最终确认
    # 这里的 "{xor}" + base64(xor_result) 是一种非常常见的模式
    encoded_b64 = base64.b64encode(encrypted_pass.encode()).decode()
    return "{xor}" + encoded_b64


# 注意：上面是一个常见的加密逻辑推测，但你的学校可能有变种。
# 另一种更简单的常见密码格式是直接提交明文密码。
# 如果加密版失败了，可以尝试直接用 my_password。


# --- 3. 自动获取本机IP和MAC地址 ---
# (这部分代码不变，为简洁省略，使用之前的即可)
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


# --- 4. 构造并发送GET登录请求 ---

login_base_url = "http://10.2.5.251:801/eportal/"
timestamp = int(time.time() * 1000)

# !! 新的挑战：部分eportal需要预先获取一个challenge/token
# 我们暂时用一个固定的或者基于IP的简单值，如果不行再进行抓包分析
# 很多时候这个challenge就是IP本身或者一个固定字符串
challenge_key = user_ip

# 加密密码
# 如果这个加密逻辑不对，服务器就无法解密，可能报"username error"
# 注意：最简单的 portal 可能不需要加密，直接用 my_password
# 我们先尝试不加密，因为`username is error`也可能是字面意思
# encoded_pass = encode_password(my_password, challenge_key, "") # 暂时不用复杂的加密

login_params = {
    "c": "Portal",
    "a": "login",
    "callback": f"dr{timestamp}",
    "login_method": "1",
    "user_account": full_user_account,
    "user_password": my_password,  # <-- 先尝试用明文密码
    "wlan_user_ip": user_ip,
    "wlan_user_mac": user_mac,
    "wlan_ac_ip": "10.2.4.1",  # <-- 根据第一次的URL线索，填上这个值
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

        # 对返回的msg也尝试进行Base64解码
        decoded_message = message
        try:
            decoded_message = base64.b64decode(message).decode("utf-8")
        except:
            pass  # 如果解码失败，就用原消息

        if (
            "认证成功" in decoded_message
            or "认证成功" in message
            or result.get("result") == "1"
        ):
            print(f"✅ 登录成功！服务器消息: {decoded_message}")
        else:
            print(f"❌ 登录失败！服务器消息: {decoded_message}")
            if "密码错误" in decoded_message:
                print("   请检查你的密码, 或者此脚本的加密逻辑可能需要调整。")
            if "username is error" in decoded_message:
                print("   请检查学号和运营商后缀(@telecom)是否正确。")

    except (AttributeError, json.JSONDecodeError):
        print("❌ 解析返回数据失败。")
        print("   原始返回内容:", jsonp_text)

except requests.exceptions.RequestException as e:
    print(f"❌ 登录请求失败。错误: {e}")
