import os
import uuid
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
APP_ROUTE = os.path.dirname(os.path.abspath(__file__))
app.config['SECRET_KEY'] = 'shhhhitsasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

COLORS = [
    ('red', 'Red'),
    ('ora', 'Orange'),
    ('yel', 'Yellow'),
    ('gre', 'Green'),
    ('blu', 'Blue'),
    ('ind', 'Indigo'),
    ('vio', 'Violet'),
    ('pin', 'Pink'),
    ('whi', 'White'),
    ('bla', 'Black'),
    ('bro', 'Brown')
]




class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    uploads = db.relationship('Upload', backref='owner')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(50), unique=True)
    clothing_type = db.Column(db.String(6))
    color = db.Column(db.String(20))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = StringField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(min=6, max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = StringField('password', validators=[InputRequired(), Length(min=8, max=80)])


class UploadForm(FlaskForm):
    type = SelectField('type', choices=[('top', 'Top'), ('bot', 'Bottom'), ('sho', 'Shoes')])
    color = SelectField('color', choices=COLORS)


class SelectColorsForm(FlaskForm):
    top_color = SelectField('top color', choices=COLORS)
    bottom_color = SelectField('bottom color', choices=COLORS)
    shoe_color = SelectField('shoe color', choices=COLORS)


@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        return '<h1>Invalid username or password.</h1>'

    return render_template('index.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('index'))

    return render_template('signup.html', form=form)


@app.route('/login')
def login():
    return


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    target = os.path.join(APP_ROUTE, 'images/')

    if not os.path.isdir(target):
        os.mkdir(target)

    for upload in request.files.getlist('file'):
        filename = upload.filename
        fileextension = filename.rsplit('.', 1)[-1]
        new_filename = str(uuid.uuid4()) + '.' + fileextension
        destination = '/'.join([target, new_filename])
        print('CURRENT USER ID: {}'.format(current_user.id))
        new_upload = Upload(filename=destination, owner=current_user)
        db.session.add(new_upload)
        db.session.commit()
        upload.save(destination)

    return render_template('complete.html', image_name=filename)


@app.route('/upload/<filename>')
@login_required
def send_image(filename):
    return send_from_directory('images', filename)


@app.route('/upload-clothes/', methods=['GET', 'POST'])
@login_required
def upload_clothes():
    form = UploadForm()

    if form.validate_on_submit():
        target = os.path.join(APP_ROUTE, 'images/')

        if not os.path.isdir(target):
            os.mkdir(target)

        for upload in request.files.getlist('file'):
            filename = upload.filename
            fileextension = filename.rsplit('.', 1)[-1]
            new_filename = str(uuid.uuid4()) + '.' + fileextension
            destination = '/'.join([target, new_filename])
            new_upload = Upload(filename=new_filename, clothing_type=form.type.data, color=form.color.data, owner=current_user)
            db.session.add(new_upload)
            db.session.commit()

            upload.save(destination)
            return render_template('complete.html', image_name=new_filename)

    return render_template('uploadclothes.html', name=current_user.username, form=form)


@app.route('/outfits', methods=['GET', 'POST'])
def view_outfits():
    form = SelectColorsForm()

    tops = Upload.query.filter_by(clothing_type='top', color='red').all()
    bottoms = Upload.query.filter_by(clothing_type='bot', color='red').all()
    shoes = Upload.query.filter_by(clothing_type='sho', color='red').all()

    return render_template('outfits.html', name=current_user.username, form=form)


@app.route('/outfits/<type>/<color>')
def retrieve_outfits(type, color):

    clothes = Upload.query.filter_by(clothing_type=type, color=color).all()
    clothesArray = []

    for c in clothes:
        clothesObj = {}
        clothesObj['filename'] = c.filename
        clothesObj['clothing_type'] = c.clothing_type
        clothesObj['color'] = c.color
        clothesArray.append(clothesObj)

    return jsonify({'clothes': clothesArray})


if __name__ == '__main__':
    app.run(debug=True)
