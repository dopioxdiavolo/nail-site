from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from forms import RegistrationForm, LoginForm
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_required, current_user
from flask_login import logout_user, login_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vetclinicdata.db'
app.config['SECRET_KEY'] = 'very-secret-key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tittle = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    photo = db.Column(db.String(200), nullable=False)




login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/main")
@app.route("/")
def main():
    return render_template('main.html')


@app.route('/feedback')
def feedback():
    return render_template('feedback.html')


@app.route("/about")
def about():
    return render_template('about.html')


@app.route('/doctors')
def doctors():
    doctors_list = Doctor.query.order_by(Doctor.experience.desc()).all()
    return render_template('doctors.html', doctors=doctors_list)


@app.route('/services')
def services():
    services_list = Service.query.order_by(Service.price).all()
    return render_template('services.html', services=services_list)


@app.route("/profile")
@login_required
def profile():
    return render_template('profile.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main'))


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_users(user_id):
    return User.query.get(int(user_id))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    
    form = LoginForm()  # Нужно создать форму входа
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('profile'))
        flash('Неверный email или пароль', 'danger')
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Пользователь с таким email уже существует', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=form.username.data).first():
            flash('Это имя пользователя уже занято', 'danger')
            return redirect(url_for('register'))
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            created_at=datetime.utcnow()
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        login_user(user)  # Автоматический вход после регистрации
        return redirect(url_for('profile'))
    
    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)