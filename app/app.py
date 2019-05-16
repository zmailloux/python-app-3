from flask import Flask,render_template, request, session, redirect, url_for
import hashlib
import flask_login
import socket

app = Flask(__name__)
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'
users = {'admin': {'password': '69bc0cc4b50ac0342dfcecdde7091587'}}


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(username):
    if username not in users:
        return

    user = User()
    user.id = username
    return user


@login_manager.request_loader
def request_loader(request):
    username = request.form.get('username')
    if username not in users:
        return

    user = User()
    user.id = username

    # DO NOT ever store passwords in plaintext and always compare password
    # hashes using constant-time comparison!
    encoded_pw = str(hashlib.md5(request.form['password'].encode()).hexdigest())
    user.is_authenticated = encoded_pw == users[username]['password']
    return user


@app.route("/index")
@flask_login.login_required
def index():
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        return render_template('index.html', hostname=host_name, ip=host_ip)
    except:
        return render_template('error.html')


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():

    #https://github.com/maxcountryman/flask-login
    if request.method == 'GET':
        if not session.get('logged_in'):
            return render_template('login.html')
        else:
            return redirect(url_for('index'))

    username = request.form['username']
    encoded_pw = str(hashlib.md5(request.form['password'].encode()).hexdigest())

    if encoded_pw == users[username]['password']:
        user = User()
        user.id = username
        flask_login.login_user(user)
        session['logged_in'] = True
        return redirect(url_for('index'))

    return 'Bad login'


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
