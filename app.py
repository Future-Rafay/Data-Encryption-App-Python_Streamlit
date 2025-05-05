# SecureVault: A Streamlit App for Secure Data Storage

import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# --- File Configuration --- #
USERS_FILE = "users.json"
DATA_FILE = "data.json"
KEY_FILE = "secret.key"

# --- Session State Init --- #
if "username" not in st.session_state:
    st.session_state.username = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Key Generation / Loading --- #


def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as file:
        file.write(key)
    return key


def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as file:
        return file.read()


# --- Load Key & Cipher --- #
KEY = load_key()
cipher = Fernet(KEY)

# --- Helper Functions --- #


def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(plain_text: str) -> str:
    return cipher.encrypt(plain_text.encode()).decode()


def decrypt_data(encrypted_text: str) -> str:
    return cipher.decrypt(encrypted_text.encode()).decode()


def load_json_file(filename: str) -> dict:
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json_file(filename: str, data: dict):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


# --- UI Setup --- #
st.set_page_config(page_title="SecureVault", page_icon="🔐", layout="centered")
st.markdown("<h1 style='text-align: center;'>🔐 SecureVault</h1>",
            unsafe_allow_html=True)
st.markdown("<h4 style='text-align: center; color: gray;'>Your encrypted vault for sensitive data</h4>",
            unsafe_allow_html=True)
st.markdown("---")

menu = ["🏠 Home", "📝 Register", "🔑 Login", "📂 Store", "🔍 Retrieve"]
choice = st.sidebar.radio("📂 Navigation", menu)

# --- Home Page --- #
if choice == "🏠 Home":
    st.markdown("""
    ### 👋 Welcome to SecureVault
    Keep your confidential data encrypted and accessible only to you.

    #### 🔐 Features:
    - Multi-user authentication
    - SHA-256 hashed passwords
    - AES-grade encryption with Fernet
    - Secure persistent storage
    - Lockout after 3 failed attempts
    """)

# --- Registration --- #
elif choice == "📝 Register":
    st.subheader("📝 Register New Account")
    new_user = st.text_input("Choose a Username")
    new_pass = st.text_input("Create a Password", type="password")

    if st.button("Register"):
        users = load_json_file(USERS_FILE)
        if new_user in users:
            st.error("❌ Username already exists!")
        else:
            users[new_user] = hash_passkey(new_pass)
            save_json_file(USERS_FILE, users)
            st.success("✅ Registered successfully! You can now log in.")

# --- Login --- #
elif choice == "🔑 Login":
    st.subheader("🔑 User Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        users = load_json_file(USERS_FILE)
        if users.get(username) == hash_passkey(password):
            st.session_state.username = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.error("❌ Invalid credentials")

# --- Store Encrypted Data --- #
elif choice == "📂 Store":
    if not st.session_state.username:
        st.warning("⚠️ You must be logged in to store data.")
    else:
        st.subheader("📂 Store Secure Data")
        secret_text = st.text_area("Enter the data you want to encrypt")
        secret_pass = st.text_input(
            "Set a decryption passkey", type="password")

        if st.button("Encrypt & Save"):
            if secret_text and secret_pass:
                data = load_json_file(DATA_FILE)
                encrypted = encrypt_data(secret_text)
                data[st.session_state.username] = {
                    "encrypted_text": encrypted,
                    "passkey_hash": hash_passkey(secret_pass)
                }
                save_json_file(DATA_FILE, data)
                st.success("✅ Your data has been encrypted and saved!")
                st.code(encrypted, language="text")
            else:
                st.error("⚠️ Both fields are required.")

# --- Retrieve Decrypted Data --- #
elif choice == "🔍 Retrieve":
    if not st.session_state.username:
        st.warning("⚠️ You must be logged in to retrieve data.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        data = load_json_file(DATA_FILE)
        user_data = data.get(st.session_state.username)

        if user_data:
            passkey = st.text_input(
                "Enter your decryption passkey", type="password")

            if st.button("Decrypt"):
                if hash_passkey(passkey) == user_data.get("passkey_hash"):
                    decrypted = decrypt_data(user_data["encrypted_text"])
                    st.success("✅ Data decrypted successfully:")
                    st.code(decrypted, language="text")
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(
                        f"❌ Wrong passkey. Attempts left: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.error(
                            "🔒 Too many failed attempts. You've been logged out.")
                        st.session_state.username = None
                        st.session_state.failed_attempts = 0
        else:
            st.warning("📭 No encrypted data found for your account.")

# --- Footer --- #
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; font-size: 0.9em; color: gray;'>
        © 2025 SecureVault. Made with ❤️ by 
        <strong><a href='https://www.linkedin.com/in/rafay-nadeem-web-developer/' 
        target='_blank' style='color: gray; text-decoration: none;'>Future Rafay</a></strong>.
    </div>
    """,
    unsafe_allow_html=True
)
