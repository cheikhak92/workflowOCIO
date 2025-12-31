from flask import Flask, render_template, url_for, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import flash


app = Flask(__name__)

app.config['SECRET_KEY'] = 'workflow-ocio-secret-key-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
app.app_context().push()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    tasks = db.relationship('Todo', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Todo(db.Model):
    __tablename__ = 'todo'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='BACKLOG')
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return '<Task %r>' % self.id
    
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect('/')
        return "Login incorrect"

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


@app.route('/signup', methods=['POST'])

def signup():
    username = request.form['username']
    password = request.form['password']

    # Vérifier si l'utilisateur existe déjà
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash("Nom d'utilisateur déjà utilisé !")
        return redirect('/login')
    
    # Vérifier s'il existe déjà des utilisateurs
    user_count = User.query.count()

    # Créer le nouvel utilisateur
    new_user = User(username=username)

    # SI c’est le premier utilisateur → admin
    if user_count == 0:
        new_user.is_admin = True

    new_user.set_password(password)

    db.session.add(new_user)
    db.session.commit()

    flash("Compte créé avec succès ! Vous pouvez vous connecter.")
    return redirect('/login')

@app.route('/users')
@login_required
def users():
    if not current_user.is_admin:
        return "Accès refusé", 403
    
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/users/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_user(id):

    if not current_user.is_admin and id != current_user.id:
        return "Accès refusé", 403

    user = User.query.get_or_404(id)

    if request.method == 'POST':
        user.username = request.form['username']

        if request.form['password']:
            user.set_password(request.form['password'])
        # Seul un admin peut modifier is_admin
        if current_user.is_admin:
            user.is_admin = True if request.form.get('is_admin') == 'on' else False
        
        # Empêcher qu'il n'y ait plus aucun admin
        if current_user.is_admin and user.is_admin == False:
            admin_count = User.query.filter_by(is_admin=True).count()
            if admin_count == 1 and user.id == current_user.id:
                return "Impossible de retirer le dernier admin", 400


        db.session.commit()
        return redirect('/users' if current_user.is_admin else '/')

    return render_template('update_user.html', user=user)

@app.route('/users/delete/<int:id>')
@login_required
def delete_user(id):

    if not current_user.is_admin:
        return "Accès refusé", 403
    
    user = User.query.get_or_404(id)

    # Empêcher un utilisateur de se supprimer lui-même
    if user.id == current_user.id:
        return "Impossible de supprimer son propre compte"

    db.session.delete(user)
    db.session.commit()
    return redirect('/users')



@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        new_task = Todo(
            content=request.form['content'],
            user_id=current_user.id
        )

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/')    
        except:
            return 'There was an issue adding your task'
    else:

        tasks = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.date_created).all()
        return render_template('index.html', tasks=tasks)


@app.route('/delete/<int:id>')

def delete(id):
    task_to_delete = Todo.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/')
    except:
        return 'There was a problem deleting that task'

@app.route('/update/<int:id>', methods=['GET', 'POST'])

def update(id):
    task = Todo.query.get_or_404(id)

    if request.method == 'POST':
        task.content = request.form['content']
        task.status = request.form['status']

        try:
            db.session.commit()
            return redirect('/')
        except:
            return 'There was an issue updating your task'

    else:
        return render_template('update.html', task=task)
    
if __name__ == "__main__":
    app.run(debug=True) 
