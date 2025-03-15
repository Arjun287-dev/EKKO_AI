import streamlit as st
from huggingface_hub import InferenceClient
import random
from astrapy.db import AstraDB
import uuid
from datetime import datetime
import hashlib
import requests

# Constants
USER_AVATAR = "👤"
BOT_AVATAR = "🤖"

# API Keys and Endpoints
HUGGINGFACE_API_KEY = "HF_KEY"
ASTRA_DB_TOKEN = "ASTRA_DB_TOKEN"
ASTRA_DB_ENDPOINT = "ASTRA_DB_ENDPOINT"

# Database and API Initialization
def initialize_services():
    db = AstraDB(token=ASTRA_DB_TOKEN, api_endpoint=ASTRA_DB_ENDPOINT)
    
    def get_or_create_collection(name):
        collections = db.get_collections()['status']['collections']
        return db.create_collection(name) if name not in collections else db.collection(name)
    
    return (
        get_or_create_collection("users"),
        get_or_create_collection("chat_sessions"),
        get_or_create_collection("messages"),
        InferenceClient(api_key=HUGGINGFACE_API_KEY)
    )

# Initialize global services
users_collection, sessions_collection, messages_collection, client = initialize_services()

# Session State Management
def initialize_session_state():
    required_keys = {
        "all_sessions": {},
        "current_session": None,
        "messages": [],
        "context": "",
        "last_input": "",
        "editing_session_name": False,
        "authenticated": False,
        "user_email": None,
        "username": None,
        "current_session_id": None,
        "new_password": None,
        "forgetEmail": None,
        "otp_sent": False,
        "otp_verify": None,
        "show_signup": False,
        "render_OTP": False,
        "render_forget_password": False,
        "otp_timestamp": None,  # Add timestamp for OTP expiration
        "otp_attempts": 0       # Track failed attempts
    }
    
    for key, default_value in required_keys.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

# User Authentication Functions
def create_user(email, username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    user_doc = {
        "_id": str(uuid.uuid4()), 
        "email": email, 
        "username": username, 
        "password": hashed_password, 
        "created_at": datetime.now().isoformat()
    }
    users_collection.insert_one(user_doc)
    return "[SUCCESS]"

def verify_user(email, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    try:
        user = users_collection.find_one({"email": email})

        if not user or 'data' not in user:
            st.error("User not found. Please try again.")
            return None
            
        user_data = user['data']['document']
            
        if user_data['password'] != hashed_password:
            st.error("Incorrect password. Please try again.")
            return None
            
        return user_data['username']

    except Exception as e:
        st.error(f"Incorrect email. Please try again.")
        return None
    
def new_password(email, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    users_collection.update_one({"email": email}, {"$set": {"password": hashed_password}})
    return True

def check_email(email):
    try:
        user = users_collection.find_one({"email": email})
        
        # Debug print to see the actual structure
        print(f"User lookup structure: {user}")
        
        # Check if response contains a document
        if user and 'data' in user and 'document' in user['data']:
            return user['data']['document']['email'] == email
            
        return False
    
    except Exception as e:
        print(f"Error checking email: {str(e)}")
        st.error(f"Error checking email: {str(e)}")
        return False
        
def otpEmail(email):
    
    otp = random.randint(100000, 999999)

    url = "https://send-bulk-emails.p.rapidapi.com/api/send/otp/mail"

    payload = {
        "subject": "Password Recovery OTP",
        "from": "gateway@eczsolutions.com",
        "to": f"{email}",
        "senders_name": "EKKO AI",
        "body": f"Your OTP is {otp}"
    }

    headers = {
        "x-rapidapi-key": "e448bfa06emsh9053d11a8be63ddp188ae7jsnf440b6eadba1",
        "x-rapidapi-host": "send-bulk-emails.p.rapidapi.com",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        data = response.json()
        
        print(f"API response: {data}")  # Debug print
        
        if response.status_code == 200:
            return otp
        else:
            st.error(f"Failed to send OTP: {data.get('message', 'Unknown error')}")
            return None
    except Exception as e:
        st.error(f"Failed to send OTP: {str(e)}")
        return None    

# Chat Session Management Functions
def save_session(email, session_name):
    session_id = str(uuid.uuid4())
    session_doc = {
        "_id": session_id, 
        "email": email,
        "session_name": session_name, 
        "created_at": datetime.now().isoformat()
    }
    sessions_collection.insert_one(session_doc)
    return session_id

def save_message(session_id, role, content):
    message_doc = {
        "_id": str(uuid.uuid4()), 
        "session_id": session_id,
        "role": role, 
        "content": content, 
        "timestamp": datetime.now().isoformat()
    }
    messages_collection.insert_one(message_doc)
    return True

def get_user_sessions(email):
    if not email:
        return []
    response = sessions_collection.find({'email': email})
    return [{
        '_id': doc['_id'], 
        'session_name': doc['session_name'],
        'created_at': doc.get('created_at', '')
    } for doc in response['data']['documents']]

def get_session_messages(session_id):
    response = messages_collection.find({"session_id": session_id})
    return sorted(response['data']['documents'], key=lambda x: x['timestamp'])

# AI Query Function
def query_huggingface(context, question):
    try:
        messages = [
            {"role": "system", "content": "You are a funny and friendly AI and most important thing is you should answer in short and concise manner not giving long answers. Be honest, funny, and slightly cursed."},
            {"role": "user", "content": f"Context: {context}\nQuestion: {question}"}
        ]
        completion = client.chat.completions.create(
            model="deepseek-ai/DeepSeek-R1-Distill-Qwen-32B", 
            messages=messages, 
            max_tokens=1000
        )
        return completion.choices[0].message['content'].strip()
    except Exception as e:
        st.error(f"Error: {e}")
        return "Sorry, I'm having trouble thinking right now. My brain cells are on strike! Please try again."

# UI Components - Chat Interface
def chat_interface():
    initialize_session_state()
    st.set_page_config(layout="wide", initial_sidebar_state="expanded")
    with st.sidebar:
        render_sidebar()
    render_main_content()

def render_sidebar():
    st.title("EKKO AI")
    if st.button("New Chat"): 
        handle_new_chat()
    
    if st.session_state.current_session_id:
        if st.session_state.editing_session_name:
            new_name = st.text_input("Rename session:", value=st.session_state.current_session, key="session_rename_input")
            if st.button("Save", key="save_edit_btn"):
                sessions_collection.update_one({"_id": st.session_state.current_session_id}, {"$set": {"session_name": new_name}})
                st.session_state.current_session = new_name
                st.session_state.editing_session_name = False
                st.rerun()
            if st.button("Cancel", key="cancel_edit_btn"):
                st.session_state.editing_session_name = False
                st.rerun()
        else:
            col1, col2 = st.columns([4, 1])
            with col1: 
                st.markdown(f"**{st.session_state.current_session}**")
            with col2: 
                if st.button("✏️"): 
                    st.session_state.editing_session_name = True
                    st.rerun()

    sessions = get_user_sessions(st.session_state.user_email)
    if sessions:
        st.markdown("#### History:")
        for session in sessions:
            if st.button(f" {session['session_name']}", key=f"session_{session['_id']}"):
                st.session_state.current_session_id = session['_id']
                st.session_state.current_session = session['session_name']
                st.session_state.messages = [
                    {"role": msg['role'], "content": msg['content']} 
                    for msg in get_session_messages(session['_id'])
                ]
                st.rerun()

    st.markdown("---")
    if st.button("Logout"): 
        reset_session_state()
    st.caption("🚀 Powered by EKKO | © 2025")

def render_main_content():
    initialize_session_state()
    with st.columns([6,1])[1]: 
        render_user_profile()
    display_chat_history()
    handle_user_input()

def render_user_profile():
    st.write(f"Welcome {st.session_state.username}!")

def display_chat_history():
    initialize_session_state()
    if not st.session_state.messages: 
        st.info("💬 Start a new conversation!")
    else:
        for message in st.session_state.messages:
            with st.chat_message("user" if message['role'] == 'user' else "assistant",
                               avatar=USER_AVATAR if message['role'] == 'user' else BOT_AVATAR):
                st.markdown(message['content'])

def handle_user_input():
    if not st.session_state.current_session_id:
        new_session_id = save_session(st.session_state.user_email, f"Chat {len(get_user_sessions(st.session_state.user_email)) + 1}")
        st.session_state.current_session_id = new_session_id
        st.session_state.current_session = f"Chat {len(get_user_sessions(st.session_state.user_email))}"

    user_input = st.chat_input("Ask EKKO anything...")
    if user_input and user_input != st.session_state.last_input:
        st.session_state.last_input = user_input
        
        with st.chat_message("user", avatar=USER_AVATAR):
            st.markdown(user_input)
            
        with st.chat_message("assistant", avatar=BOT_AVATAR):
            message_placeholder = st.empty()
            message_placeholder.text("🤔 Thinking...")
            
            try:
                save_message(st.session_state.current_session_id, "user", user_input)
                response = query_huggingface(st.session_state.context, user_input)
                save_message(st.session_state.current_session_id, "assistant", response)
                
                st.session_state.messages.extend([
                    {"role": "user", "content": user_input},
                    {"role": "assistant", "content": response}
                ])
                message_placeholder.markdown(response)
                
            except Exception as e:
                message_placeholder.error(f"Sorry, something went wrong! {str(e)}")

def reset_session_state():
    for key in list(st.session_state.keys()): 
        del st.session_state[key]
    initialize_session_state()

def handle_new_chat():
    if st.session_state.current_session_id and st.session_state.messages:
        sessions_collection.update_one(
            {"_id": st.session_state.current_session_id}, 
            {"$set": {"session_name": st.session_state.current_session}}
        )
    st.session_state.update({
        "messages": [], 
        "context": "", 
        "current_session_id": None,
        "current_session": None, 
        "last_input": ""
    })
    st.rerun()

# UI Components - Authentication Pages
def auth_pages():
    initialize_session_state()
    if st.session_state.show_signup: 
        render_signup_page()
    elif st.session_state.render_OTP: 
        render_otp_page()
    elif st.session_state.render_forget_password: 
        render_forget_password_page()
    else: 
        render_login_page()

def render_login_page():
    st.title("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Login"):
            if username := verify_user(email, password):
                st.session_state.update(authenticated=True, user_email=email, username=username)
                st.rerun()
    with col2:
        if st.button("Go to Signup"):
            st.session_state.show_signup = True
            st.rerun()
    with col3:
        if st.button("Forget Password"):
            st.session_state.render_OTP = True
            st.rerun()

def render_otp_page():
    st.title("Forget Password")
    st.subheader("Enter your email to reset password")
    
    # Initialize state if not already done
    if "forgetEmail" not in st.session_state:
        st.session_state.forgetEmail = None
    if "otp_sent" not in st.session_state:
        st.session_state.otp_sent = False
    if "otp_verify" not in st.session_state:
        st.session_state.otp_verify = None
    
    # Email input
    forgetEmail = st.text_input("Email", value=st.session_state.forgetEmail or "")
    
    # Send OTP button logic
    if st.button("Send OTP"):
        if not forgetEmail:
            st.error("Please enter your email address.")
            return
        
        # Validate email format first
        if '@' not in forgetEmail or '.' not in forgetEmail:
            st.error("Please enter a valid email address.")
            return
            
        # First, check if the email exists in the database
        email_exists = check_email(forgetEmail)
        
        if not email_exists:
            st.error("Email not found. Please enter a registered email address.")
            return
            
        # If email exists, try to send OTP
        otp_verify = otpEmail(forgetEmail)
        
        # Only update state if OTP was successfully sent
        if otp_verify:
            st.session_state.forgetEmail = forgetEmail
            st.session_state.otp_verify = otp_verify
            st.session_state.otp_sent = True
            st.success("OTP sent successfully! Please check your email.")
        else:
            # OTP sending failed
            st.error("Failed to send OTP. Please try again later.")
    
    # Only show OTP verification if an OTP was actually sent
    if st.session_state.otp_sent and st.session_state.otp_verify:
        st.markdown("---")
        st.subheader("OTP Verification")
        otp = st.text_input("Enter the OTP sent to your email", key="otp_input")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Verify OTP"):
                if not otp:
                    st.error("Please enter the OTP.")
                elif otp == str(st.session_state.otp_verify):
                    st.success("OTP verified successfully!")
                    # Set state to show password reset form
                    st.session_state.render_forget_password = True
                    st.session_state.render_OTP = False
                    st.rerun()
                else:
                    st.error("Invalid OTP. Please try again.")
        
        with col2:
            if st.button("Resend OTP"):
                new_otp = otpEmail(st.session_state.forgetEmail)
                if new_otp:
                    st.session_state.otp_verify = new_otp
                    st.success("New OTP sent successfully!")
                else:
                    st.error("Failed to resend OTP. Please try again.")
    
    # Back to login button
    st.markdown("---")
    if st.button("Back to Login"):
        # Reset all OTP-related state
        st.session_state.render_OTP = False
        st.session_state.otp_sent = False
        st.session_state.otp_verify = None
        st.session_state.forgetEmail = None
        st.rerun()

def render_forget_password_page():
    st.title("Reset Password")
    
    if not st.session_state.forgetEmail:
        st.error("Email verification required. Please go back and verify your email.")
        if st.button("Go Back to Email Verification"):
            st.session_state.render_forget_password = False
            st.session_state.render_OTP = True
            st.rerun()
        return
    
    st.info(f"Setting new password for: {st.session_state.forgetEmail}")
    
    newPassword = st.text_input("New Password", type="password")
    newConfirmPassword = st.text_input("Confirm Password", type="password")

    if st.button("Reset Password"):
        if not newPassword or not newConfirmPassword:
            st.error("All fields are required.")
            return

        if len(newPassword) < 6:
            st.error("Password must be at least 6 characters long.")
            return
            
        if newPassword != newConfirmPassword:
            st.error("Passwords do not match.")
            return
        
        try:
            if new_password(st.session_state.forgetEmail, newPassword):
                st.success("Password reset successfully!")
                
                # Add a delay to show the success message before redirecting
                import time
                time.sleep(2)
                
                # Reset state and redirect to login
                st.session_state.render_forget_password = False
                st.session_state.forgetEmail = None
                st.session_state.otp_sent = False
                st.session_state.otp_verify = None
                st.rerun()
        except Exception as e:
            st.error(f"Failed to reset password: {str(e)}")

    if st.button("Back to Login"):
        # Reset all OTP-related state
        st.session_state.render_forget_password = False
        st.session_state.forgetEmail = None
        st.session_state.otp_sent = False
        st.session_state.otp_verify = None
        st.rerun()


def render_signup_page():
    st.title("Sign Up")
    email = st.text_input("Email")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Sign Up"):
            if not email or not username or not password or not confirm_password:
                st.error("All fields are required.")
                return
                
            if '@' not in email or '.' not in email:
                st.error("Please enter a valid email address.")
                return
                
            if len(username) < 3:
                st.error("Username must be at least 3 characters long.")
                return
                
            if len(password) < 6:
                st.error("Password must be at least 6 characters long.")
                return
                
            if password != confirm_password:
                st.error("Passwords do not match.")
                return
                
            if create_user(email, username, password) == "[SUCCESS]":
                st.success("Account created successfully!")
                st.session_state.update(authenticated=True, user_email=email, username=username)
                st.rerun()
    
    with col2:
        if st.button("Back to Login"):
            st.session_state.show_signup = False
            st.rerun()

# Main Application
if __name__ == "__main__":
    initialize_session_state()
    if st.session_state.authenticated: 
        chat_interface()
    else: 
        auth_pages()