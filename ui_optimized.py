import tkinter as tk
from tkinter import ttk
import requests
import socket
import time
import re
import json
import os
from getmac import get_mac_address
import threading  # 1. 导入 threading 和 queue
import queue
import base64

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

        try:
            decoded_message = base64.b64decode(message).decode("utf-8")
        except (ValueError, TypeError, base64.binascii.Error):
            decoded_message = message

        return "认证成功" in message or result.get("result") == "1", decoded_message

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
        # 使用一个通常不会被墙且响应快的HTTP网站，避免HTTPS握手开销
        requests.get("http://detectportal.firefox.com/success.txt", timeout=2)
        return True
    except requests.exceptions.RequestException:
        return False


# ==============================================================================
# GUI 应用主类 (这部分重构)
# ==============================================================================
class LoginApp:
    # --- 优化: 将常量定义为类属性 ---
    OPERATOR_MAP = {"电信": "@telecom", "移动": "@cmcc", "联通": "@unicom"}
    REVERSE_OPERATOR_MAP = {v: k for k, v in OPERATOR_MAP.items()}

    def __init__(self, master):
        self.master = master
        master.title("校园网自动登录")
        win_width, win_height = 350, 240  # 稍微调整窗口大小以容纳新组件
        x = (master.winfo_screenwidth() / 2) - (win_width / 2)
        y = (master.winfo_screenheight() / 2) - (win_height / 2)
        master.geometry(f"{win_width}x{win_height}+{int(x)}+{int(y)}")
        master.resizable(False, False)

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar()

        # --- 优化: 使用一个 Frame 来容纳可变内容，方便清理 ---
        self.container = tk.Frame(master)
        self.container.pack(fill="both", expand=True)

        # --- 2. 为线程通信创建队列 ---
        self.task_queue = queue.Queue()
        # --- 3. 启动队列处理器 ---
        self.master.after(100, self.process_queue)

    def clear_container(self):
        """销毁容器中的所有组件，实现页面切换"""
        for widget in self.container.winfo_children():
            widget.destroy()

    def toggle_password_visibility(self):
        """切换密码的可见性"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="●")

    def show_login_page(self):
        """显示登录输入界面"""
        self.clear_container()
        self.master.title("登录校园网")

        frame = tk.Frame(self.container)
        frame.pack(pady=20, padx=30)

        # 学号
        tk.Label(frame, text="学号:").grid(row=0, column=0, sticky="w", pady=5)
        e_user = tk.Entry(frame, textvariable=self.username_var, width=30)
        e_user.grid(row=0, column=1, columnspan=2)
        e_user.focus_set()  # --- UX优化: 自动聚焦 ---

        # 密码
        tk.Label(frame, text="密码:").grid(row=1, column=0, sticky="w", pady=5)
        self.password_entry = tk.Entry(
            frame, textvariable=self.password_var, width=30, show="●"
        )
        self.password_entry.grid(row=1, column=1, columnspan=2)

        # --- UX优化: 使用复选框控制密码可见性 ---
        show_pass_check = tk.Checkbutton(
            frame,
            text="显示密码",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
        )
        show_pass_check.grid(row=2, column=1, sticky="w")

        # 运营商
        tk.Label(frame, text="运营商:").grid(row=3, column=0, sticky="w", pady=5)
        self.operator_combobox = ttk.Combobox(
            frame,
            values=list(self.OPERATOR_MAP.keys()),
            state="readonly",
            width=27,
        )
        self.operator_combobox.grid(row=3, column=1, columnspan=2, sticky="ew")

        # 填充配置
        config = load_config()
        if config:
            self.username_var.set(config.get("username", ""))
            self.password_var.set(config.get("password", ""))
            saved_op = self.REVERSE_OPERATOR_MAP.get(config.get("operator"), "电信")
            self.operator_combobox.set(saved_op)
        else:
            self.operator_combobox.set("电信")

        # 登录按钮
        self.login_button = tk.Button(
            frame, text="登 录", command=self.do_login_from_input
        )
        self.login_button.config(width=25, height=1)
        self.login_button.grid(row=4, columnspan=3, pady=20)

        self.master.bind("<Return>", lambda event: self.do_login_from_input())

    def show_status_page(self, status_text, is_success):
        """显示结果/状态界面"""
        self.master.unbind("<Return>")
        self.clear_container()
        self.master.title("登录状态")

        color = "green" if is_success else "red"
        status_label = tk.Label(
            self.container,
            text=status_text,
            font=("Microsoft YaHei", 12),
            fg=color,
            wraplength=300,
        )
        status_label.pack(pady=40, padx=20)

        switch_button = tk.Button(
            self.container, text="切换/修改账号", command=self.show_login_page
        )
        switch_button.config(width=20, height=1)
        switch_button.pack(pady=10)

    # --- 4. 创建在后台线程中运行的函数 ---
    def threaded_task(self, task_func, *args):
        """将任务放入后台线程执行"""

        def task_wrapper():
            result = task_func(*args)
            self.task_queue.put(result)  # 将结果放入队列

        thread = threading.Thread(target=task_wrapper)
        thread.daemon = True  # 设置为守护线程，主程序退出时线程也退出
        thread.start()

    # --- 5. 创建队列处理器，在主线程中安全更新UI ---
    def process_queue(self):
        """处理来自工作线程的结果队列"""
        try:
            # 非阻塞地获取结果
            result = self.task_queue.get_nowait()

            # 根据返回结果的类型判断是哪个任务完成
            if isinstance(result, bool):  # 这是 check_online_status 的结果
                if result:
                    self.show_status_page("✅ 已连接到互联网，无需登录。", True)
                else:
                    self.attempt_auto_login()  # 检查失败，尝试自动登录
            elif isinstance(result, tuple):  # 这是 perform_login 的结果
                success, message = result

                # 恢复登录按钮
                if hasattr(self, "login_button"):
                    self.login_button.config(state="normal", text="登 录")

                if success:
                    # 登录成功后保存配置
                    username = self.username_var.get()
                    password = self.password_var.get()
                    selected_op = self.operator_combobox.get()
                    operator = self.OPERATOR_MAP.get(selected_op)
                    if username and password and operator:
                        save_config(username, password, operator)
                    self.show_status_page(f"✅ 登录成功！\n服务器消息：{message}", True)
                else:
                    self.show_status_page(
                        f"❌ 登录失败！\n服务器消息：{message}", False
                    )
        except queue.Empty:
            # 队列为空，什么都不做，100ms后再次检查
            pass
        finally:
            self.master.after(100, self.process_queue)

    def do_login(self, username, password, operator):
        if not username or not password:
            self.show_status_page("账号或密码不能为空！", False)
            return

        # UX优化: 禁用按钮并更新文本
        if hasattr(self, "login_button"):
            self.login_button.config(state="disabled", text="登录中...")

        # 将登录任务放入后台线程
        self.threaded_task(perform_login, username, password, operator)

    def do_login_from_input(self):
        """从输入框获取信息并登录"""
        username = self.username_var.get()
        password = self.password_var.get()
        selected_display_name = self.operator_combobox.get()
        operator_value = self.OPERATOR_MAP.get(selected_display_name, "@telecom")
        self.do_login(username, password, operator_value)

    def attempt_auto_login(self):
        """尝试使用配置文件自动登录"""
        config = load_config()
        if config and all(k in config for k in ["username", "password", "operator"]):
            self.username_var.set(config["username"])  # 预填充，以便登录成功后保存
            self.password_var.set(config["password"])
            op_display = self.REVERSE_OPERATOR_MAP.get(config["operator"], "电信")
            # 确保组合框存在再设置
            if hasattr(self, "operator_combobox"):
                self.operator_combobox.set(op_display)
            else:  # 如果在状态页，需要临时创建以保存值
                self.operator_combobox = ttk.Combobox(self.container)
                self.operator_combobox.set(op_display)

            self.do_login(config["username"], config["password"], config["operator"])
        else:
            self.show_login_page()

    def start_flow(self):
        """程序的启动流程"""
        # 将网络检查也放入后台线程
        self.threaded_task(check_online_status)


# ==============================================================================
# 程序入口
# ==============================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    app.start_flow()
    root.mainloop()
