import openai
import re
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'



app.secret_key = 'Ahmed'  # secret key



users = {} 

# Add a new user to the dictionary for testing purposes
users['new_user'] = {
    'username': 'new_user',
    'password': generate_password_hash('new_password', method='pbkdf2:sha256', salt_length=8)
}

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/')
def default():
    # If the user is already logged in, redirect to the home page.
    if 'user' in session:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')


@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('home'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        
        if existing_user:
            flash('Username already exists')
            return render_template('signup.html')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            new_user = User(username=username, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created, please log in.')
            return redirect(url_for('login'))
    else:
        return render_template('signup.html')
    

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username

with app.app_context():
    db.create_all()


@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')  # Use the correct template here

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/diagnose', methods=['GET', 'POST'])
def diagnose():
    if request.method == 'POST':
        symptoms = request.form['symptoms']
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo-0125", 
                messages=[
                    {"role": "system", "content": "you are an assistant that takes the users symptoms and predicts the disease according to the ones he provided give the most 5 common or closest to the symptoms provided and rank them from the most likely to the least likely. You should also describe the each disease you get and explain what is usually the reason a person gets this disease also always provide which doctor to seek for every disease but in the line that you state the disease. you shall understand any language given in the input of the symptoms and give the output which is the diseases and the explanation and give the give the most 5 common or closest to the symptoms provided and rank them from the most likely to the least likely with which doctor to visit in the same language that the user inputed the symptoms with."},
                    {"role": "user", "content": symptoms}
                ]
                
            )
            
            diagnosis = response.choices[0].message['content']
            
            # Now parse the response into a list of dictionaries
            diseases = []
            for line in diagnosis.split('\n'):
                if line.strip().startswith('1.') or line.strip().startswith('2.') or line.strip().startswith('3.') or line.strip().startswith('4.') or line.strip().startswith('5.'):
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        diseases.append({'name': parts[0].strip(), 'description': parts[1].strip()})
            
        except Exception as e:
            diseases = [{'name': 'Error', 'description': str(e)}]
        
        return render_template('diagnosis.html', diseases=diseases)
    else:
        return render_template('diagnose.html')
if __name__ == '__main__':
    app.run(debug=True, port=5007)

