from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import google.generativeai as genai
import sqlite3
import json # Import json for settings
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
CORS(app, supports_credentials=True) # Enable CORS for frontend interaction and credentials
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY", "0497af52cd3b20884d4dff764a98649a2fda7fb314790cbaf0067f184f1da121") # Important for sessions

# --- Gemini API Configuration ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    raise ValueError("AIzaSyDNZostm9Lt0iRIl2odPxBLW39Rg-QapIw")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-2.5-flash') 

# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Not strictly needed for API, but good practice

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def get_id(self):
        return str(self.id)

# --- SQLite Database Setup ---
DATABASE = 'gosearch_users.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                user_id INTEGER PRIMARY KEY,
                settings_json TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()

# Call init_db once at the start of the application
init_db()

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            return User(*user_data)
        return None

@app.route('/')
def home():
    return "Gosearch Backend is running!"

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    password_hash = generate_password_hash(password)

    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            user_id = cursor.lastrowid
            # Initialize default settings for new user
            default_settings = {"dark_mode": True, "safe_search": False}
            cursor.execute("INSERT INTO user_settings (user_id, settings_json) VALUES (?, ?)", 
                           (user_id, json.dumps(default_settings)))
            conn.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()

    if user_data:
        user = User(*user_data)
        if check_password_hash(user.password_hash, password):
            login_user(user)
            return jsonify({"message": "Logged in successfully", "username": user.username}), 200
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200

@app.route('/api/user', methods=['GET'])
def get_user_status():
    if current_user.is_authenticated:
        return jsonify({"is_authenticated": True, "username": current_user.username}), 200
    else:
        return jsonify({"is_authenticated": False}), 200

@app.route('/api/settings', methods=['GET'])
@login_required
def get_settings():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT settings_json FROM user_settings WHERE user_id = ?", (current_user.id,))
        settings_data = cursor.fetchone()
        if settings_data:
            return jsonify(json.loads(settings_data[0])), 200
        # Return default settings if none found
        return jsonify({"dark_mode": True, "safe_search": False}), 200

@app.route('/api/settings', methods=['POST'])
@login_required
def save_settings():
    data = request.get_json()
    # Basic validation, more robust validation can be added
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid settings format"}), 400
    
    settings_json = json.dumps(data)

    try:
        with sqlite3.connect(DATABASE) as conn:
            cursor = conn.cursor()
            cursor.execute("REPLACE INTO user_settings (user_id, settings_json) VALUES (?, ?)", 
                           (current_user.id, settings_json))
            conn.commit()
        return jsonify({"message": "Settings saved successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    if not query:
        return jsonify({"error": "Search query is missing"}), 400

    try:
        # Send the query to Gemini AI
        response = model.generate_content(f"Provide search results for: {query}. Format the response as a JSON array of objects, where each object has 'title', 'link', and 'snippet' fields. The link field should be a plausible URL related to the title. Ensure the JSON is properly formatted and enclosed in a single code block.")
        
        # Extract the text from the Gemini response
        gemini_text = response.text.strip()

        # Attempt to parse the JSON output from Gemini
        # Gemini might include markdown ```json ... ``` or other formatting
        if gemini_text.startswith('```json'):
            gemini_text = gemini_text[len('```json'):]
            if gemini_text.endswith('```'):
                gemini_text = gemini_text[:-len('```')]
        
        # Fallback for simple JSON or if markdown wasn't present
        results = jsonify(json.loads(gemini_text)) # Ensure results are always JSON parsed here
        
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        # Return a more descriptive error or fallback to dummy results
        results = [
            {"title": f"Error searching for {query}", "link": "#", "snippet": f"Could not retrieve results: {e}"},
        ]
        return jsonify(results), 500
    
    return jsonify(results)

if __name__ == '__main__':
    # It's good practice to run Flask in production with a WSGI server
    # For development, app.run is fine.
    app.run(debug=True)
