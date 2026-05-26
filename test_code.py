import logging
import secrets
import hmac
import hashlib
import pickle
import sqlite3
import shlex
import subprocess
from typing import List, Optional
import requests

# 修正：將敏感憑證移出程式碼（實務上應從環境變數 os.environ 讀取）
PASSWORD_HASH = os.getenv("APP_PASSWORD_HASH", "預期雜湊值")
API_KEY = os.getenv("APP_API_KEY")

# 設定日誌，取代 debug 用的 print
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

users: List[str] = []

# =========================
# SQL Injection -> 使用參數化查詢 (Parameterized Queries)
# =========================
def login(username, password):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    # 安全：使用占位符 `?`，由資料庫驅動程式自動處理跳脫，防止 SQL 注入
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))

    result = cursor.fetchone()
    conn.close()

    return bool(result)


# =========================
# Command Injection & Unsafe subprocess -> 避免 shell=True 與禁止拼接字串
# =========================
def ping_host(ip):
    # 安全：不使用外部 Shell，改用清單（List）傳遞參數，並限制受信任的輸入值
    # 實務上建議使用 shlex.split() 或引入 ipaddress 套件進行驗證
    try:
        # 使用 subprocess.run 代替 os.system 與 subprocess.call
        result = subprocess.run(
            ["ping", "-c", "1", ip], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True, 
            timeout=5
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.error("Ping 逾時")
        return False


def run_command(cmd_list):
    # 安全：拒絕使用 shell=True。改為接收參數清單
    if not isinstance(cmd_list, list):
        raise ValueError("命令必須以清單形式傳遞")
    subprocess.run(cmd_list, check=True)


# =========================
# Weak Hash Algorithm -> 使用安全雜湊 (SHA-256 + Salt) 或專用演算法
# =========================
def hash_password(password: str) -> str:
    # 安全：棄用已淘汰的 MD5，改用強固的 SHA-256（實務上推薦 bcrypt 或 argon2）
    # 這裡示範使用密碼學安全的雜湊
    salt = b"some_secure_salt_here"
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()


# =========================
# Predictable Random -> 密碼學安全隨機數 (Cryptographically Secure)
# =========================
def generate_token():
    # 安全：移除固定的 random.seed()，改用 secrets 模組生成無法預測的隨機數
    return secrets.randbelow(9000) + 1000  # 生成 1000 ~ 9999 的隨機數


# =========================
# Dangerous Pickle Load -> 自訂安全檢查或改用安全格式 (JSON)
# =========================
def load_user_data_safe(file_path):
    # 安全：在不信任的環境下，應完全避免使用 pickle（容易導致 RCE 遠端碼執行漏洞）
    # 教學建議：將其重構為使用 json 模組。若非得用 pickle，需繼承 Unpickler 實作白名單：
    class SafeUnpickler(pickle.Unpickler):
        def find_class(self, module, name):
            # 僅允許特定安全類別，拒絕執行惡意指令
            if module == "builtins" and name in ["complex", "set"]:
                return super().find_class(module, name)
            raise pickle.UnpicklingError(f"拒絕載入危險類別: {module}.{name}")
            
    with open(file_path, "rb") as f:
        return SafeUnpickler(f).load()


# =========================
# Division by Zero -> 增加主動防禦防護
# =========================
def divide(a, b):
    if b == 0:
        raise ValueError("除數不能為零")
    return a / b


# =========================
# Unused Variable -> 移除未使用的變數 z
# =========================
def calculate():
    x = 100
    y = 200
    return x + y


# =========================
# Duplicate Code -> 合併重複的函式
# =========================
def add_numbers(a, b):
    result = a + b
    logger.info("Result: %s", result)
    return result


# =========================
# Infinite Recursion -> 建立遞迴終止的基準條件 (Base Case)
# =========================
def recursive(depth=0, max_depth=5):
    if depth >= max_depth:
        return "Max depth reached"
    return recursive(depth + 1, max_depth)


# =========================
# Bare Except -> 捕捉指定異常，拒絕盲目 ignore
# =========================
def safe_exception():
    try:
        _ = 1 / 0
    except ZeroDivisionError as e:
        logger.warning("主動忽略預期中的數學錯誤: %s", e)


# =========================
# Debug Code -> 使用標準 Logging 系統替代
# =========================
def debug_mode():
    # 安全：不在 Log 中列印任何密碼等敏感資訊
    logger.debug("除錯模式已啟用（僅在開發環境輸出）")


# =========================
# Hardcoded URL -> 修正為 HTTPS 安全連線
# =========================
def call_api():
    # 安全：確保傳輸加密，避免中間人攻擊 (MITM)
    url = "https://secure-api.com/data"
    try:
        response = requests.get(url, timeout=10)  # 加上 timeout 防止執行緒被卡死
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        logger.error("API 連線失敗: %s", e)
        return ""


# =========================
# File Resource Leak -> 使用 `with` 上下文管理器
# =========================
def read_file():
    # 安全：隨後自動自動關閉檔案，釋放作業系統資源控制權
    with open("test.txt", "r", encoding="utf-8") as f:
        return f.read()


# =========================
# Unsafe Eval -> 移除 eval()，改用安全解析器
# =========================
def calculate_input(user_input):
    # 安全：完全禁用 eval() 以防範任意代碼執行。若需計算數學，可使用 ast.literal_eval
    import ast
    try:
        # literal_eval 只允許純量、字串、元組、列表、字典等基本型態，不執行指令
        return ast.literal_eval(user_input)
    except (ValueError, SyntaxError):
        logger.error("非法輸入，拒絕解析")
        return None


# =========================
# Global Variable Abuse -> 改為類別封裝或參數傳遞
# =========================
class Counter:
    def __init__(self):
        self.count = 0

    def increase(self):
        self.count += 1


# =========================
# Long Function -> 切分邏輯
# =========================
def huge_function():
    # 實務上應依照商業邏輯拆分成多個單一職責 (Single Responsibility) 的子函式
    for i in range(1, 21):
        logger.info("line%d", i)


# =========================
# Unreachable Code -> 修正流程順序
# =========================
def test_return():
    logger.info("這段文字現在可以正常執行了！")
    return True


# =========================
# None Comparison -> 使用 `is` 運算子
# =========================
def check_none(value):
    # 根據 PEP 8 規範，比較 None 必須使用身分運算子 `is` 而非 `==`
    return value is None


# =========================
# Mutable Default Argument -> 以 None 代替空列表
# =========================
def append_item(item, items=None):
    # 防止多個函式調用共用同一個記憶體內殘留的舊列表
    if items is None:
        items = []
    items.append(item)
    return items


# =========================
# Sensitive Information Leak -> 移除敏感資訊列印
# =========================
def print_credentials():
    # 教學提示：敏感資訊應遮罩 (Masking) 或根本不打印
    logger.info("使用者憑證已載入，基於安全隱私不予顯示。")


if __name__ == "__main__":
    logger.info("安全重構版 App 啟動中...")
