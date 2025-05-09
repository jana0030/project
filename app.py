from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
import os
import bcrypt
from bcrypt import gensalt, hashpw, checkpw
from sqlalchemy import LargeBinary
import bleach



#app = Flask(__name__)

app = Flask(__name__, template_folder=os.path.join(os.getcwd(), 'templates'))
print("Available templates:", app.jinja_env.list_templates())



print(app.template_folder)
print("Current working directory:", os.getcwd())



# Setup database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key_here'  # Used for sessions

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'admin' or 'user'
    password = db.Column(LargeBinary, nullable=False)

    def __repr__(self):
        return f"<User {self.username}, Role {self.role}>"
    
# Define the Comment model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"<Comment by {self.user}>"


@app.before_request
def create_fake_users():
    db.create_all()  # Ensure database tables are created

    # Check if there are already users to avoid duplicates
    if not User.query.first():
        
        # Create hashed passwords for the fake users
        fake_user1_password = "adminpass"
        fake_user2_password = "userpass"

        # Generate salt and hash passwords
        salt = gensalt()

        # Hash the passwords using bcrypt
        hashed_password1 = hashpw(fake_user1_password.encode('utf-8'), salt)
        hashed_password2 = hashpw(fake_user2_password.encode('utf-8'), salt)

        # Create user objects with hashed passwords
        fake_user1 = User(username="adminUser", role="admin", password=hashed_password1)
        fake_user2 = User(username="normalUser", role="user", password=hashed_password2)


        db.session.add(fake_user1)
        db.session.add(fake_user2)
        db.session.commit()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="Username already taken.")

        # Hash the password
        salt = gensalt()
        hashed_password = hashpw(password.encode('utf-8'), salt)

        # Create a new user with the default role 'user'
        new_user = User(username=username, role='user', password=hashed_password)

        # Save the user to the database
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


#@app.route('/')

#@app.route('/', methods=['GET', 'POST'])
#def login():
#    if request.method == 'POST':
#        username = request.form.get('username')
#        password = request.form.get('password')
#
#        user = User.query.filter_by(username=username, password=password).first()
#        if user:
#            session['username'] = user.username
#            session['role'] = user.role
#            if user.role == 'admin':
#                return redirect(url_for('admin'))
#            else:
#                return redirect(url_for('user_home'))
#        else:
#            # Pass an error message to the login template
#            return render_template('login.html', error="Invalid username or password.")

#    return render_template('login.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and checkpw(password.encode('utf-8'), user.password):
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('dashboard'))  # Redirect both to one dashboard
        else:
            return render_template('login.html', error="Invalid username or password.")

    return render_template('login.html')


@app.route('/user')
def user_home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('forbidden.html', username=session['username'])


@app.route('/admin')
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    if user and user.role == 'admin':
        return render_template('admin.html', username=user.username)
    else:
        return render_template('forbidden.html'), 403


# unautherized access
#def login():
#    return render_template('login.html')


#@app.route('/admin', methods=['GET', 'POST'])
#def admin():
#    if request.method == 'POST':
#        username = request.form.get('username')
#        password = request.form.get('password')  # optional
#        return render_template('admin.html', username=username)
#    else:
#        return redirect(url_for('login'))


    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))



@app.route('/profile/<username>')
def profile(username):
    if 'username' not in session or session['username'] != username:
        return redirect(url_for('login'))

    
    user = User.query.filter_by(username=username).first_or_404()

    return render_template('profile.html', user=user)  


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch the user from the database
    user = User.query.filter_by(username=session['username']).first()

    # Handle comment submission
    if request.method == 'POST':
        content = request.form.get('content')

        # Sanitize the comment content to avoid XSS
        sanitized_content = bleach.clean(content)

        # Save the sanitized comment to the database
        comment = Comment(user=user.username, content=sanitized_content)
        db.session.add(comment)
        db.session.commit()

        # Redirect back to the dashboard after posting a comment
        return redirect(url_for('dashboard'))

    # Fetch all comments to display on the dashboard
    comments = Comment.query.all()

    return render_template('dashboard.html', user=user, comments=comments)



if __name__ == '__main__':
    app.run(debug=True)
