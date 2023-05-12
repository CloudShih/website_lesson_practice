from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Email, Length
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, Table, Column, Integer
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from functools import wraps
from forms import CommonForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
# gravatar = Gravatar(app,
#                     size=100,
#                     rating="g",
#                     default="robohash",
#                     force_default=False,
#                     force_lower=False,
#                     use_ssl=False,
#                     base_url=None)

gravatar = Gravatar(app, default="robohash")


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(int(user_id))


def delete_all():
    all_user = db.session.query(User).all()
    for user in all_user:
        db.session.delete(user)
        db.session.close()
        db.session.commit()
        print("done")


def check_admin(func):
    @wraps(func)
    def new_func():
        if current_user.admin != True:
            return abort(403)
        return func()
    return new_func

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    comments = relationship("Comment", back_populates="parent_post")

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    admin = db.Column(db.Boolean, default=bool(0), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


class RegisterForm(FlaskForm):
    email = StringField(label="Email", validators=[InputRequired(), Email()])
    password = PasswordField(label="Password", validators=[InputRequired(), Length(min=8)])
    name = StringField(label="Name", validators=[InputRequired()])
    submit = SubmitField(label="Submit")


class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[InputRequired(), Email()])
    password = PasswordField(label="Password", validators=[InputRequired(), Length(min=8)])
    submit = SubmitField(label="Submit")

@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts, check_login=current_user.is_authenticated, user=current_user)


@app.route('/register', methods=["POST", "GET"])
def register():
    register_Form = RegisterForm()
    if register_Form.validate_on_submit():
        pwd = request.form["password"]
        new_user = User(email=request.form["email"],
                        password=generate_password_hash(pwd, "pbkdf2:sha256", 8),
                        name=request.form["name"]
                        )
        existed_user = db.session.query(User).filter_by(email=new_user.email).first()
        if existed_user:
            flash("This email has been existed, please login directly.")
            return redirect(url_for("register"))
        else:
            db.session.add(new_user)
            db.session.commit()
            if len(db.session.query(User).all()) == 1:
                user = db.session.query(User).get(1)
                user.admin = bool(1)
                db.session.commit()
            # login_user(new_user)
            return redirect(url_for("login"))
    return render_template("register.html", form=register_Form, check_login=current_user.is_authenticated)


@app.route('/login', methods=["POST", "GET"])
def login():
    print(current_user)
    print(current_user.is_authenticated)
    check_user = LoginForm()
    if check_user.validate_on_submit():
        user = db.session.query(User).filter_by(email=request.form["email"]).first()
        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return redirect(url_for("get_all_posts"))
        elif not user:
            flash("This Email does not exist, please try again.")
            return redirect("login")
        elif not check_password_hash(user.password, request.form["password"]):
            flash("This password is incorrect, please try again.")
            return redirect("login")
    return render_template("login.html", form=check_user, check_login=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts', check_login=current_user.is_authenticated, user=current_user))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = db.session.query(BlogPost).get(post_id)
    form = CommonForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(text=request.form["comment_text"],
                              comment_author=current_user,
                              parent_post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", form=form, post=requested_post, check_login=current_user.is_authenticated, user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", check_login=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", check_login=current_user.is_authenticated)


@app.route("/new-post", methods=["POST", "GET"])
@check_admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=request.form["title"],
            subtitle=request.form["subtitle"],
            body=request.form["body"],
            img_url=request.form["img_url"],
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts", check_login=current_user.is_authenticated, user=current_user))
    return render_template("make-post.html", form=form, check_login=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@check_admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, user=current_user))

    return render_template("make-post.html", form=edit_form, check_login=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@check_admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', check_login=current_user.is_authenticated, user=current_user))


if __name__ == "__main__":
    # delete_all()
    # User.__table__.drop(db.engine)
    # db.create_all()
    # db.drop_all()
    app.run(debug=True, host="localhost", port=5001)
