import streamlit as st
from huggingface_hub import InferenceClient
from astrapy.db import AstraDB
import uuid
from datetime import datetime

USER_AVATAR = "👤"
BOT_AVATAR = "🤖"

HUGGINGFACE_API_KEY = "API_KEY"
ASTRA_DB_TOKEN = "API_KEY"
ASTRA_DB_ENDPOINT = "ENDPOINT"

def initialize_services():
    db = AstraDB(token=ASTRA_DB_TOKEN, api_endpoint=ASTRA_DB_ENDPOINT)
    
    def get_or_create_collection(name):#get or create the collection
        collections = db.get_collections()['status']['collections']#get the collections from the database
        return db.create_collection(name) if name not in collections else db.collection(name)#create the collection if it is not in the database
    
    return (
        get_or_create_collection("users"),
        get_or_create_collection("chat_sessions"),
        get_or_create_collection("messages"),
        InferenceClient(api_key=HUGGINGFACE_API_KEY)
    )

users_collection, sessions_collection, messages_collection, client = initialize_services()

def initialize_session_state():#initialize the session state
    required_keys = {
        "all_sessions": {},#all the sessions
        "current_session": None,#the current session
        "messages": [],#the messages
        "context": "",#the context
        "last_input": "",#the last input
        "editing_session_name": False,#the editing session name
        "authenticated": False,#the authenticated
        "user_email": None,#the user email  
        "username": None,#the username
        "current_session_id": None#the current session id
    }
    

    for key, default_value in required_keys.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

initialize_session_state()

#User creation with email, username, password
def create_user(email, username, password):
    user_doc = {
        "_id": str(uuid.uuid4()), "email": email, 
        "username": username, "password": password,
        "created_at": datetime.now().isoformat()
    }#format of the user storage in the database
    users_collection.insert_one(user_doc)#insert the user document into the users collection
    return "[SUCCESS]"

#User verification with email and password
def verify_user(email, password):
    try:
        user = users_collection.find_one({"email": email}) #find the user document in the users collection

        if not user or 'data' not in user:
            st.error("User not found. Please try again.")#if the user document is not found or the data is not found
            return None
            
        user_data = user['data']['document']#get the user data from the user document
            
        if user_data['password'] != password:
            st.error("Incorrect password. Please try again.")#if the password is incorrect 
            return None
            
        return user_data['username']#return the username if the password is correct

    except Exception as e:
        st.error(f"Incorrect email. Please try again.")#if the email is incorrect
        return None

#Save the session with email and session name
def save_session(email, session_name):
    session_id = str(uuid.uuid4())#generate a unique session id
    session_doc = {
        "_id": session_id, "email": email,
        "session_name": session_name, "created_at": datetime.now().isoformat()
    }
    sessions_collection.insert_one(session_doc)#insert the session document into the sessions collection
    return session_id#return the session id

#Save the message with session id, role, and content
def save_message(session_id, role, content):
    message_doc = {
        "_id": str(uuid.uuid4()), "session_id": session_id, #generate a unique message id
        "role": role, "content": content, "timestamp": datetime.now().isoformat()
    }
    messages_collection.insert_one(message_doc)#insert the message document into the messages collection
    return True

#Get the user sessions with email
def get_user_sessions(email):
    if not email:
        return[]
    response = sessions_collection.find({'email':email})#find the session document in the sessions collection
    return [{
        '_id': doc['_id'], 'session_name': doc['session_name'],
        'created_at': doc.get('created_at', '')
    } for doc in response['data']['documents']]#return the session documents

#Get the session messages with session id
def get_session_messages(session_id):
    response = messages_collection.find({"session_id": session_id})#find the message document in the messages collection
    return sorted(response['data']['documents'], key=lambda x: x['timestamp'])#return the message documents

#Query the huggingface model with context and question
def query_huggingface(context, question):
    try:
        messages = [
                {"role": "system", "content": "You are an funny and friendly AI and most important thing is you should answer in short and concise manner not giving long answers. Be honest, funny, and slightly cursed."},
                {"role": "user", "content": f"Context: {context}\nQuestion: {question}"}
            ]
        completion = client.chat.completions.create(
            model="deepseek-ai/DeepSeek-R1-Distill-Qwen-32B", messages=messages, max_tokens=1000
        )
        return completion.choices[0].message['content'].strip()#return the completion
    except Exception as e:
        st.error(f"Error: {e}")
        return "Sorry, I'm having trouble thinking right now. My brain cells are on strike! Please try again."

def chat_interface():
    initialize_session_state()  # Initialize before rendering
    st.set_page_config(layout="wide", initial_sidebar_state="expanded")
    with st.sidebar:#sidebar
        render_sidebar()#render the sidebar
    render_main_content()#render the main content

def render_sidebar():#render the sidebar
    st.title("EKKO AI")#title
    if st.button("New Chat"): handle_new_chat()#handle the new chat
    
    
    if st.session_state.current_session_id:#if the current session id is not none
        if st.session_state.editing_session_name:#if the editing session name is not none
            new_name = st.text_input("Rename session:", value=st.session_state.current_session, key="session_rename_input")#new name
            if st.button("Save", key="save_edit_btn"):#save the edit
                sessions_collection.update_one({"_id": st.session_state.current_session_id}, {"$set": {"session_name": new_name}})#update the session name
                st.session_state.current_session = new_name
                st.session_state.editing_session_name = False
                st.rerun()
            if st.button("Cancel", key="cancel_edit_btn"): #cancel the edit
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
    if st.button("logout"): reset_session_state()
    st.caption("🚀 Powered by EKKO | © 2025")

def render_main_content():#render the main content
    initialize_session_state()  # Ensure initialization
    with st.columns([6,1])[1]: 
        render_user_profile()
    display_chat_history()
    handle_user_input()

def render_user_profile():#render the user profile
    st.write(f"Welcome {st.session_state.username}!")

def display_chat_history():#display the chat history
    initialize_session_state()  # Verify initialization
    if not st.session_state.messages: 
        st.info("💬 Start a new conversation!")
    else:
        for message in st.session_state.messages:#for the message in the messages
            with st.chat_message("user" if message['role'] == 'user' else "assistant",#if the role is user then show the user avatar else show the bot avatar
                               avatar=USER_AVATAR if message['role'] == 'user' else BOT_AVATAR):#if the role is user then show the user avatar else show the bot avatar
                st.markdown(message['content'])#show the message content

def handle_user_input():#handle the user input
    if not st.session_state.current_session_id:#if the current session id is not none
        new_session_id = save_session(st.session_state.user_email, f"Chat {len(get_user_sessions(st.session_state.user_email)) + 1}")#save the session
        st.session_state.current_session_id = new_session_id#update the current session id
        st.session_state.current_session = f"Chat {len(get_user_sessions(st.session_state.user_email))}"

    user_input = st.chat_input("Ask EKKO anything...")  # Changed from text_input to chat_input
    if user_input and user_input != st.session_state.last_input:#if the user input is not none and the user input is not the last input
        st.session_state.last_input = user_input#update the last input
        
        # Show user message immediately
        with st.chat_message("user", avatar=USER_AVATAR):#show the user avatar
            st.markdown(user_input)#show the user input
            
        # Show "thinking" message while generating response
        with st.chat_message("assistant", avatar=BOT_AVATAR):#show the bot avatar
            message_placeholder = st.empty()#show the message placeholder
            message_placeholder.text("🤔 Thinking...")#show the thinking message
            
            try:
                save_message(st.session_state.current_session_id, "user", user_input)#save the user input   
                response = query_huggingface(st.session_state.context, user_input)#query the huggingface model
                save_message(st.session_state.current_session_id, "assistant", response)#save the response
                
                # Update messages state and replace placeholder with response
                st.session_state.messages.extend([
                    {"role": "user", "content": user_input},
                    {"role": "assistant", "content": response}
                ])
                message_placeholder.markdown(response)
                
            except Exception as e:
                message_placeholder.error(f"Sorry, something went wrong! {str(e)}")

def reset_session_state():#reset the session state
    for key in list(st.session_state.keys()): del st.session_state[key]

def handle_new_chat():#handle the new chat
    if st.session_state.current_session_id and st.session_state.messages:
        sessions_collection.update_one({"_id": st.session_state.current_session_id}, {"$set": {"session_name": st.session_state.current_session}})
    st.session_state.update({
        "messages": [], "context": "", "current_session_id": None,
        "current_session": None, "last_input": ""
    })
    st.rerun()

def auth_pages():#auth pages
    if st.session_state.get('show_signup'): render_signup_page()#render the signup page
    else: render_login_page()#render the login page

def render_login_page():#render the login page
    st.title("Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    if st.columns(1)[0].button("Login"):
        if username := verify_user(email, password):
            st.session_state.update(authenticated=True, user_email=email, username=username)
            st.rerun()
    if st.columns(5)[4].button("Go to Signup"):
        st.session_state.show_signup = True
        st.rerun()

def render_signup_page():#render the signup page
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
    
    if st.columns(5)[4].button("Back to Login"):
        st.session_state.show_signup = False
        st.rerun()

if __name__ == "__main__":#main
    initialize_session_state()  # Initial call
    if st.session_state.authenticated: 
        chat_interface()
    else: 
        auth_pages()