from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from bcrypt import gensalt, hashpw, checkpw
from dotenv import load_dotenv, set_key, find_dotenv
from db import get_database
from os import getenv
import generate_secret

app = Flask(__name__)
dotenv_file = find_dotenv()
load_dotenv(dotenv_file)

secret_key = getenv('JWT_SECRET_KEY', '')

if secret_key == '':
    print('Generating secret key')
    secret_key = generate_secret()
    set_key(dotenv_file, 'JWT_SECRET_KEY', str(secret_key))

app.config["JWT_SECRET_KEY"] = getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)

host = getenv('MONGO_HOST', 'localhost')
port = getenv('MONGO_PORT', '27017')
dbname = getenv('MONGO_DBNAME', '')
username = getenv('MONGO_USERNAME', 'root')
password = getenv('MONGO_PASSWORD', 'password')
authSource = getenv('MONGO_AUTH_SOURCE', 'admin')

app.config['MONGO_URI'] = f'mongodb://{username}:{password}@{host}:{port}/{dbname}?authSource={authSource}'

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    db = get_database()
    
    user = db.users.find_one({"username": username })

    if user == None:
        return jsonify({"msg": "Bad username or password"}), 401

    if not checkpw(password.encode(), user['password'].encode()):
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get("username", None)
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    if username == None:
        return jsonify({"msg": "Missing username"}), 422
    if password == None:
        return jsonify({"msg": "Missing password"}), 422
    if email == None:
        return jsonify({"msg": "Missing email"}), 422

    
    db = get_database()
    
    usernameExists = db.users.find_one({ "username": username }) != None

    if usernameExists:
        return jsonify({"msg": "Username already exists"}), 409
    
    emailExists = db.users.find_one({ "email": email }) != None

    if emailExists:
        return jsonify({"msg": "Email already exists"}), 409
    
    salt = gensalt()
    hashed_password = hashpw(password.encode(), salt).decode()
    
    db.users.insert_one({
        'username': username,
        'password': hashed_password,
        'email': email,    
    })

    return jsonify(
        message="User created successfully",
    )

@app.route("/home", methods=["GET"])
@jwt_required()
def home():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == "__main__":
    app.run()