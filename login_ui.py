import tkinter as tk
from tkinter import ttk  # 导入ttk模块以使用Combobox
import requests
import socket
import time
import re
import json
import os
from getmac import get_mac_address

CONFIG_FILE = "config.json"


# ==============================================================================
# 核心登录逻辑 (这部分不变)
# ==============================================================================
def perform_login(username, password, operator):
    """
    执行登录操作并返回结果。
    :return: (bool, str) -> (是否成功, 消息)
    """
    full_user_account = f"{username}{operator}"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.2.5.251", 80))
        user_ip = s.getsockname()[0]
        s.close()
        user_mac = get_mac_address()
        if not user_mac:
            raise Exception("MAC address not found")
        user_mac = user_mac.replace(":", "").replace("-", "").lower()
    except Exception as e:
        return False, f"无法获取网络信息: {e}\n请确保已连接校园网WiFi。"

    timestamp = int(time.time() * 1000)
    login_params = {
        "c": "Portal",
        "a": "login",
        "callback": f"dr{timestamp}",
        "login_method": "1",
        "user_account": full_user_account,
        "user_password": password,
        "wlan_user_ip": user_ip,
        "wlan_user_mac": user_mac,
        "wlan_ac_ip": "10.2.4.1",
        "wlan_ac_name": "NAS",
        "jsVersion": "3.0",
        "_": timestamp,
    }
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(
            "http://10.2.5.251:801/eportal/",
            params=login_params,
            headers=headers,
            timeout=5,
        )
        response.encoding = "utf-8"
        json_str = re.search(r"\((.*)\)", response.text).group(1)
        result = json.loads(json_str)
        message = result.get("msg", "")
        return ("认证成功" in message or result.get("result") == "1"), message
    except requests.exceptions.RequestException:
        return False, "网络请求失败，认证服务器无响应。"
    except (AttributeError, json.JSONDecodeError):
        return False, f"解析服务器响应失败: {response.text}"


# ==============================================================================
# 配置文件读写 (这部分不变)
# ==============================================================================
def save_config(username, password, operator):
    config_data = {"username": username, "password": password, "operator": operator}
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config_data, f)


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return None
    return None


# ==============================================================================
# 网络状态检查 (这部分不变)
# ==============================================================================
def check_online_status():
    try:
        requests.get("https://www.baidu.com", timeout=2)
        return True
    except requests.exceptions.RequestException:
        return False


# ==============================================================================
# GUI 应用主类 (这部分有修改)
# ==============================================================================
class LoginApp:
    def __init__(self, master):
        self.master = master
        master.title("校园网自动登录")
        win_width, win_height = 320, 200
        x = (master.winfo_screenwidth() / 2) - (win_width / 2)
        y = (master.winfo_screenheight() / 2) - (win_height / 2)
        master.geometry(f"{win_width}x{win_height}+{int(x)}+{int(y)}")
        master.resizable(False, False)

        # --- 新增: 运营商显示名到实际值的映射 ---
        self.operator_map = {"电信": "@telecom", "移动": "@cmcc", "联通": "@unicom"}
        self.reverse_operator_map = {v: k for k, v in self.operator_map.items()}

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.widgets = []

        # 将密码输入框和下拉框保存为实例变量，方便访问
        self.password_entry = None
        self.operator_combobox = None

    def clear_frame(self):
        for widget in self.widgets:
            widget.destroy()
        self.widgets = []

    # --- 新增: 密码框的焦点事件处理函数 ---
    def on_password_focus_in(self, event):
        """当密码框获得焦点时，显示明文"""
        self.password_entry.config(show="")

    def on_password_focus_out(self, event):
        """当密码框失去焦点时，用●隐藏密码"""
        self.password_entry.config(show="●")

    def show_login_page(self):
        """显示登录输入界面"""
        self.clear_frame()
        self.master.title("登录校园网")

        frame = tk.Frame(self.master)
        frame.pack(pady=20, padx=20)
        self.widgets.append(frame)

        tk.Label(frame, text="学号:").grid(row=0, column=0, sticky="w", pady=5)
        e_user = tk.Entry(frame, textvariable=self.username_var, width=25)
        e_user.grid(row=0, column=1)

        tk.Label(frame, text="密码:").grid(row=1, column=0, sticky="w", pady=5)
        # --- 修改: 密码框初始化与事件绑定 ---
        self.password_entry = tk.Entry(frame, textvariable=self.password_var, width=25)
        self.password_entry.grid(row=1, column=1)
        self.password_entry.bind("<FocusIn>", self.on_password_focus_in)
        self.password_entry.bind("<FocusOut>", self.on_password_focus_out)
        self.password_entry.config(show="●")  # 默认隐藏

        tk.Label(frame, text="运营商:").grid(row=2, column=0, sticky="w", pady=5)
        # --- 修改: 使用 ttk.Combobox ---
        self.operator_combobox = ttk.Combobox(
            frame,
            values=list(self.operator_map.keys()),
            state="readonly",  # 用户只能选择，不能输入
            width=22,
        )
        self.operator_combobox.grid(row=2, column=1, sticky="ew")

        # 尝试填充已保存的配置
        config = load_config()
        if config:
            self.username_var.set(config.get("username", ""))
            self.password_var.set(config.get("password", ""))
            # 根据保存的实际值(@telecom)找到对应的显示名(电信)
            saved_operator_display = self.reverse_operator_map.get(
                config.get("operator"), "电信"
            )
            self.operator_combobox.set(saved_operator_display)
        else:
            self.operator_combobox.set("电信")  # 默认选项

        login_button = tk.Button(frame, text="登 录", command=self.do_login_from_input)
        # 修改: 设置按钮大小
        login_button.config(width=20, height=1)
        login_button.grid(row=3, columnspan=2, pady=15)

        # 让回车键也能触发登录
        self.master.bind("<Return>", lambda event: self.do_login_from_input())

    def show_status_page(self, status_text, is_success):
        """显示结果/状态界面"""
        # 取消回车键绑定，避免在结果页按回车触发操作
        self.master.unbind("<Return>")
        self.clear_frame()
        self.master.title("登录状态")

        color = "green" if is_success else "red"
        status_label = tk.Label(
            self.master, text=status_text, font=("Arial", 12), fg=color, wraplength=300
        )
        status_label.pack(pady=40, padx=20)
        self.widgets.append(status_label)

        switch_button = tk.Button(
            self.master, text="切换/修改账号", command=self.show_login_page
        )
        switch_button.config(width=20, height=1)
        switch_button.pack(pady=10)
        self.widgets.append(switch_button)

    def do_login(self, username, password, operator):
        """执行登录并更新UI"""
        if not username or not password:
            self.show_status_page("账号或密码不能为空！", False)
            return

        success, message = perform_login(username, password, operator)
        if success:
            save_config(username, password, operator)
            self.show_status_page(f"✅ 登录成功！\n服务器消息: {message}", True)
        else:
            self.show_status_page(f"❌ 登录失败！\n服务器消息: {message}", False)

    def do_login_from_input(self):
        """从输入框获取信息并登录"""
        username = self.username_var.get()
        password = self.password_var.get()
        # --- 修改: 从Combobox获取选择，并映射到实际值 ---
        selected_display_name = self.operator_combobox.get()
        operator_value = self.operator_map.get(
            selected_display_name, "@telecom"
        )  # 安全获取

        self.do_login(username, password, operator_value)

    def start_flow(self):
        """程序的启动流程"""
        if check_online_status():
            self.show_status_page("✅ 已连接到互联网，无需登录。", True)
            return

        config = load_config()
        if config:
            username = config.get("username")
            password = config.get("password")
            operator = config.get("operator")
            # 检查配置是否完整
            if username and password and operator:
                self.do_login(username, password, operator)
            else:  # 配置不完整，显示登录页
                self.show_login_page()
        else:
            self.show_login_page()


# ==============================================================================
# 程序入口
# ==============================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    app.start_flow()
    root.mainloop()
