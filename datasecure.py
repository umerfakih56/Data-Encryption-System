import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
from datetime import datetime

# === Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# === Session State Setup ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# === Load and Save Data ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# === Key Generation and Hashing ===
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# === Encryption and Decryption ===
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# === App Content ===
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

stored_data = load_data()

# === Home Page ===
if choice == "Home":
    st.subheader("Welcome to Umer's 🔒 Data Encryption System")
    st.markdown("""
        - 🔐 Secure your sensitive notes or data using a unique encryption key.
        - 🔑 Login required to access or manage stored data.
        - ❌ 3 failed login attempts lead to a temporary lockout.
        - ☁️ No external database — data is stored locally in encrypted format.
    """)

# === Register Page ===
elif choice == "Register":
    st.subheader("🖋️ Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username in stored_data:
            st.warning("⚠️ Username already exists.")
        elif username and password:
            stored_data[username] = {
                "password": hash_password(password),
                "data": []
            }
            save_data(stored_data)
            st.success("✅ User registered successfully!")
        else:
            st.error("❗ Both fields are required.")

# === Login Page ===
elif choice == "Login":
    st.subheader("🔑 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏰ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"👋 Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid Credentials! Attempts left: {remaining}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Too many failed attempts. Try again after 60 seconds.")
                st.stop()

# === Store Encrypted Data ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("📝 Store Encrypted Data")
        title = st.text_input("Enter a title for the data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if title and data and passkey:
                encrypted_title = encrypt_text(title, passkey)
                encrypted_data = encrypt_text(data, passkey)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                stored_data[st.session_state.authenticated_user]["data"].append({
                    "title": encrypted_title,
                    "content": encrypted_data,
                    "timestamp": timestamp
                })
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("❗ All fields are required.")

# === Retrieve Encrypted Data ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("⚠️ Please login first.")
    else:
        st.subheader("🔓 Retrieve & Decrypt Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found!")
        else:
            st.markdown("### Encrypted Entries")
            for idx, entry in enumerate(user_data):
                st.code(f"{idx+1}. {entry['title']} | {entry['timestamp']}")

            index = st.number_input("Enter Entry Number to Decrypt", min_value=1, max_value=len(user_data), step=1)
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                selected = user_data[index - 1]
                decrypted_title = decrypt_text(selected["title"], passkey)
                decrypted_data = decrypt_text(selected["content"], passkey)
                if decrypted_data:
                    st.success(f"✅ Title: {decrypted_title}")
                    st.text_area("🔓 Decrypted Data", decrypted_data, height=200)
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")

# === Footer Branding ===
st.markdown("---")
st.markdown("Developed by 'M.Umer Fakih' | GIAIC Rising Star 🌟 | [LinkedIn](https://www.linkedin.com/in/muhammad-umer-fakih-3a5a642b8/)")