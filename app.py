import os
from enum import unique

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_login import (login_user, LoginManager, login_required,
                         current_user, logout_user)
from wtforms import StringField, SubmitField, EmailField, TextAreaField, SelectField, PasswordField
from wtforms.validators import DataRequired, Email
from flask_bootstrap import Bootstrap5
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# app.secret_key = os.environ['SECRET_KEY']
login_manager = LoginManager()
app.secret_key = "testing"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DB_URI']
login_manager.init_app(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

bootstrap = Bootstrap5(app)

class TicketDataModel(db.Model):
    __tablename__ = 'TicketData'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String())
    text = db.Column(db.String())

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(unique=True))
    password = db.Column(db.String())
    name = db.Column(db.String())



class DataFrom(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    data = TextAreaField("Message",render_kw={'class': 'form-control', 'rows': 6}, validators=[DataRequired()])


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password",
                             validators=[DataRequired()])
    submit = SubmitField("Log In")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id)

@app.route('/', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if not user:
            flash("That email does not exist, please try again")
            return redirect(url_for('login.html'))
        elif not check_password_hash(user.password, password):
            flash("Password Incorrect. Please try again")
            return redirect(url_for('login.html'))
        else:
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template("login.html.html", form=form)



if __name__ == '__main__':
    app.run(debug=True)