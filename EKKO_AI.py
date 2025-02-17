import streamlit as st
from huggingface_hub import InferenceClient
from astrapy.db import AstraDB
import uuid
from datetime import datetime

USER_AVATAR = "👤"
BOT_AVATAR = "🤖"

HUGGINGFACE_API_KEY = "API_KEY"
ASTRA_DB_TOKEN = "TOKEN"
ASTRA_DB_ENDPOINT = "URL_ENDPOINT"

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

users_collection, sessions_collection, messages_collection, client = initialize_services()

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
        "current_session_id": None
    }
    

    for key, default_value in required_keys.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

initialize_session_state()

def create_user(email, username, password):
    user_doc = {
        "_id": str(uuid.uuid4()), "email": email, 
        "username": username, "password": password,
        "created_at": datetime.now().isoformat()
    }
    users_collection.insert_one(user_doc)
    return "[SUCCESS]"

def verify_user(email, password):
    try:
        user = users_collection.find_one({"email": email}) 

        if not user or 'data' not in user:
            st.error("User not found. Please try again.")
            return None
            
        user_data = user['data']['document']
            
        if user_data['password'] != password:
            st.error("Incorrect password. Please try again.")
            return None
            
        return user_data['username']

    except Exception as e:
        st.error(f"Incorrect email. Please try again.")
        return None

def save_session(email, session_name):
    session_id = str(uuid.uuid4())
    session_doc = {
        "_id": session_id, "email": email,
        "session_name": session_name, "created_at": datetime.now().isoformat()
    }
    sessions_collection.insert_one(session_doc)
    return session_id

def save_message(session_id, role, content):
    message_doc = {
        "_id": str(uuid.uuid4()), "session_id": session_id,
        "role": role, "content": content, "timestamp": datetime.now().isoformat()
    }
    messages_collection.insert_one(message_doc)
    return True

def get_user_sessions(email):
    if not email:
        return[]
    response = sessions_collection.find({'email':email})
    return [{
        '_id': doc['_id'], 'session_name': doc['session_name'],
        'created_at': doc.get('created_at', '')
    } for doc in response['data']['documents']]

def get_session_messages(session_id):
    response = messages_collection.find({"session_id": session_id})
    return sorted(response['data']['documents'], key=lambda x: x['timestamp'])

def query_huggingface(context, question):
    try:
        messages = [
                {"role": "system", "content": "You are an funny and friendly AI and most important thing is you should answer in short and concise manner not giving long answers. Be honest, funny, and slightly cursed."},
                {"role": "user", "content": f"Context: {context}\nQuestion: {question}"}
            ]
        completion = client.chat.completions.create(
            model="deepseek-ai/DeepSeek-R1-Distill-Qwen-32B", messages=messages, max_tokens=500
        )
        return completion.choices[0].message['content'].strip()
    except Exception as e:
        st.error(f"Error: {e}")
        return "Sorry, I'm having trouble thinking right now. My brain cells are on strike! Please try again."

def chat_interface():
    initialize_session_state()  # Initialize before rendering
    st.set_page_config(layout="wide", initial_sidebar_state="expanded")
    with st.sidebar: 
        render_sidebar()
    render_main_content()

def render_sidebar():
    st.title("EKKO AI")
    if st.button("New Chat"): handle_new_chat()
    
    if st.session_state.current_session_id:
        st.markdown("#### Current Session:")
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
            with col1: st.markdown(f"**{st.session_state.current_session}**")
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
    st.caption("🚀 Powered by EKKO | © 2025")

def render_main_content():
    initialize_session_state()  # Ensure initialization
    with st.columns([6,1])[1]: 
        render_user_profile()
    display_chat_history()
    handle_user_input()

def render_user_profile():
    st.write(f"Welcome {st.session_state.username}!")
    if st.button("logout"): reset_session_state()

def display_chat_history():
    initialize_session_state()  # Verify initialization
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

    user_input = st.chat_input("Ask EKKO anything...")  # Changed from text_input to chat_input
    if user_input and user_input != st.session_state.last_input:
        st.session_state.last_input = user_input
        
        # Show user message immediately
        with st.chat_message("user", avatar=USER_AVATAR):
            st.markdown(user_input)
            
        # Show "thinking" message while generating response
        with st.chat_message("assistant", avatar=BOT_AVATAR):
            message_placeholder = st.empty()
            message_placeholder.text("🤔 Thinking...")
            
            try:
                save_message(st.session_state.current_session_id, "user", user_input)
                response = query_huggingface(st.session_state.context, user_input)
                save_message(st.session_state.current_session_id, "assistant", response)
                
                # Update messages state and replace placeholder with response
                st.session_state.messages.extend([
                    {"role": "user", "content": user_input},
                    {"role": "assistant", "content": response}
                ])
                message_placeholder.markdown(response)
                
            except Exception as e:
                message_placeholder.error(f"Sorry, something went wrong! {str(e)}")
                
def reset_session_state():
    for key in list(st.session_state.keys()): del st.session_state[key]

def handle_new_chat():
    if st.session_state.current_session_id and st.session_state.messages:
        sessions_collection.update_one({"_id": st.session_state.current_session_id}, {"$set": {"session_name": st.session_state.current_session}})
    st.session_state.update({
        "messages": [], "context": "", "current_session_id": None,
        "current_session": None, "last_input": ""
    })
    st.rerun()

def auth_pages():
    if st.session_state.get('show_signup'): render_signup_page()
    else: render_login_page()

def render_login_page():
    st.title("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.columns(2)[0].button("Login"):
        if username := verify_user(email, password):
            st.session_state.update(authenticated=True, user_email=email, username=username)
            st.rerun()
    if st.columns(2)[0].button("Go to Signup"):
        st.session_state.show_signup = True
        st.rerun()

def render_signup_page():
    st.title("Sign Up")
    email = st.text_input("Email")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.columns(2)[0].button("Sign Up"):
        # Input validation
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
            
        # If all validation passes, create user
        if create_user(email, username, password) == "[SUCCESS]":
            st.success("Account created successfully!")
            st.session_state.update(authenticated=True, user_email=email, username=username)
            st.rerun()
    
    if st.columns(2)[0].button("Back to Login"):
        st.session_state.show_signup = False
        st.rerun()

if __name__ == "__main__":
    initialize_session_state()  # Initial call
    if st.session_state.authenticated: 
        chat_interface()
    else: 
        auth_pages()