from flask import render_template, redirect
from flask_login import login_required, logout_user

from app.main import app


@app.route('/')
def main():
    return render_template('home.html')


@app.route('/logout/')
@login_required
def logout():
    """Logout view"""
    logout_user()
    return redirect('/')
