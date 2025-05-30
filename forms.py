from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from flask_wtf.file import FileField, FileAllowed


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', 
                         validators=[DataRequired(), Length(min=4, max=64)])
    email = StringField('Email', 
                       validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', 
                           validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Повторите пароль', 
                            validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')