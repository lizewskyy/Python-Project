from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user



auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('successfull login', category='success')
            else:
                flash('incorrect password', category='error')
        else:
            flash('User does not exist', category='error')
    return render_template("login.html")
@auth.route('/logout')
def logout():
    return "<p>Logout</p>"
@auth.route('/sign-up', methods=['GET','POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email Already Is Being Used')

        if len(email) < 4:
            flash('Email must be more than 4 characters.', category="error")
            pass
        elif len(username) < 2:
            flash('Username must be more than 2 Characters', category="error")
            pass
        elif password1 != password2:
            flash('Password is not the Same', category="error")
            pass
        elif len(password1) < 7:
            flash('Password needs to be more than 7 Characters', category="error")
            pass
        else:
            new_user = User(email=email, username=username, password=generate_password_hash(password1, method='scrypt'))
            db.session.add(new_user)
            db.session.commit() 

            flash('Account Created!', category="success")

            return redirect(url_for('views.home'))

            #add to db
    return render_template("sign-up.html")
