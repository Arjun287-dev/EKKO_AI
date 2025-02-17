# EKKO AI

The EKKO AI is a chatbot which has tone of funny and friendly AI. The chatbot is built using DeepSeek R1-Distill-Qwen-32B with the help of Hugging Face and Astra DB for vector search and database.

## Link

[EKKO AI](https://ekko-ai.streamlit.app/)

## Features
- Authentication with email and password that is stored in Astra DB.
- Chatbot with tone of funny and friendly AI.
- Built with Streamlit for a clean and interactive user experience.
- LLM integration with Hugging Face.
- Chat session history is stored in Astra DB.
- Message history is stored in Astra DB.

## Prerequisites
Before running the application, ensure you have the following:
1. Python installed (version 3.6 or higher).
2. Astra DB account and token.
3. Hugging Face API key.

## Installation
1. Clone this repository:
   ```sh
   git clone <repository_url>
   ```
2. Navigate to the project directory and install the required Python packages:
   ```sh
   cd foldername
   pip install -r requirements.txt
   ```

## Running the Application
1. Replace the **API_KEY** in the code with your valid API key.
2. Start the Streamlit server by running:
   ```sh
   streamlit run filepath/filename.py
   ```
3. Open your web browser and go to [http://localhost:8501](http://localhost:8501) to use the application.

## Usage
1. Login with your email and password or signup with your email, username and password.
2. Start a new chat or continue a previous chat.
3. access the chat history from the sidebar.

## API Reference
- The application uses the **Hugging Face** for LLM integration.
- You can modify the code to use any other LLM of your choice.
- The application uses the **Astra DB** for chat history storage.
- You can modify the code to use any other database of your choice.

## Contributing
We welcome contributions! If you have any suggestions or improvements, feel free to fork the repository and submit a pull request.
- For major changes, open an issue first to discuss your proposed updates.

## Contact
For any questions or feedback, feel free to reach out:
- Email: [arjunarundiyar28@gmail.com](mailto:arjunarundiyar28@gmail.com)
- Open an issue in this repository.

