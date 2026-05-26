# vulnerable_app.py
# 此程式碼為教學用途，故意包含大量 Bug / Vulnerability / Code Smell
# 適合用 SonarQube 掃描示範

import os
import random
import subprocess
import hashlib
import pickle
import sqlite3
import requests

PASSWORD = "admin123"  # Hardcoded password
API_KEY = "SECRET-KEY-123456"  # Hardcoded secret

users = []

# =========================
# SQL Injection
# =========================
def login(username, password):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()

    # SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    cursor.execute(query)

    result = cursor.fetchone()

    conn.close()

    if result:
        return True
    else:
        return False


# =========================
# Command Injection
# =========================
def ping_host(ip):
    # Command Injection
    os.system("ping -c 1 " + ip)


# =========================
# Unsafe subprocess
# =========================
def run_command(cmd):
    subprocess.call(cmd, shell=True)


# =========================
# Weak Hash Algorithm
# =========================
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# =========================
# Predictable Random
# =========================
def generate_token():
    random.seed(123)
    return random.randint(1000, 9999)


# =========================
# Dangerous Pickle Load
# =========================
def load_user_data(file):
    with open(file, "rb") as f:
        data = pickle.load(f)
    return data


# =========================
# Division by Zero
# =========================
def divide(a, b):
    return a / b


# =========================
# Unused Variable
# =========================
def calculate():
    x = 100
    y = 200

    return x + y


# =========================
# Duplicate Code
# =========================
def add_numbers(a, b):
    result = a + b
    print("Result:", result)
    return result


def add_numbers2(a, b):
    result = a + b
    print("Result:", result)
    return result


# =========================
# Infinite Recursion
# =========================
def recursive(depth, max_depth=5):
    # 1. The Base Case: Break out if we hit the limit
    if depth >= max_depth:
        print("Reached max depth! Breaking out...")
        return "Done"
    
    print(f"Current depth: {depth}")
    
    # 2. The Recursive Case: Move closer to the base case
    return recursive(depth + 1, max_depth)


# =========================
# Bare Except
# =========================
def unsafe_exception():
    try:
        1 / 0  # Evaluated for its side effect (raising a ZeroDivisionError)
    except ZeroDivisionError:
        pass


# =========================
# Debug Code
# =========================
def debug_mode():
    print("DEBUG MODE ENABLED")
    password = "123456"
    print(password)


# =========================
# Hardcoded URL
# =========================
def call_api():
    url = "http://insecure-api.com/data"

    response = requests.get(url)

    return response.text


# =========================
# File Resource Leak
# =========================
def read_file():
    f = open("test.txt", "r")
    data = f.read()

    return data


# =========================
# Unsafe Eval
# =========================
def calculate_input(user_input):
    return eval(user_input)


# =========================
# Global Variable Abuse
# =========================
count = 0

def increase():
    global count
    count += 1


# =========================
# Long Function
# =========================
def huge_function():
    print("line1")
    print("line2")
    print("line3")
    print("line4")
    print("line5")
    print("line6")
    print("line7")
    print("line8")
    print("line9")
    print("line10")
    print("line11")
    print("line12")
    print("line13")
    print("line14")
    print("line15")
    print("line16")
    print("line17")
    print("line18")
    print("line19")
    print("line20")


# =========================
# Unreachable Code
# =========================
def test_return():
    return True


# =========================
# None Comparison
# =========================
def check_none(value):
    if value == None:
        return True
    return False


# =========================
# Mutable Default Argument
# =========================
def append_item(item, items=None):
    # Initialize the parameter inside the function
    if items is None:
        items = []
        
    items.append(item)
    return items


# =========================
# Sensitive Information Leak
# =========================
def print_credentials():
    username = "admin"
    password = "password123"

    print(username)
    print(password)


# =========================
# Main
# =========================
if __name__ == "__main__":

    print(login("admin", "admin"))

    ping_host("127.0.0.1")

    print(hash_password("mypassword"))

    print(generate_token())

    unsafe_exception()

    debug_mode()

    print(calculate_input("2 + 2"))

    huge_function()
