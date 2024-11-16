from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os
import secrets

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}}, supports_credentials=True)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Model per gli utenti
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


# Inizializzazione del database e popolamento dei prodotti
@app.before_request
def setup_database():
    # Crea tutte le tabelle nel database
    db.create_all()

# CORS handling
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Registrazione
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if 'username' not in data or 'email' not in data or 'password' not in data:
            return jsonify({'message': 'Missing fields'}), 400

        # Check if username or email already exists
        existing_user = User.query.filter((User.username == data['username']) | (User.email == data['email'])).first()
        if existing_user:
            return jsonify({'message': 'Username or email already exists'}), 400

        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user = User(username=data['username'], email=data['email'], password=hashed_password)
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 400

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print('Login data received:', data)  # Log received data
    if 'email' not in data or 'password' not in data:
        return jsonify({'message': 'Missing fields'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if user:
        print('User found:', user)  # Log user found
        if bcrypt.check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=user.id)
            return jsonify({'token': access_token})
        else:
            print('Password check failed')  # Log password check failure
    else:
        print('User not found')  # Log user not found

    return jsonify({'message': 'Invalid credentials'}), 401

# Get user info
@app.route('/user', methods=['GET'])
@jwt_required()
def user():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    print(f"Current user: {user}")
    return jsonify({'username': user.username, 'email': user.email})

if __name__ == '__main__':
    app.run(port=5001, debug=True)
