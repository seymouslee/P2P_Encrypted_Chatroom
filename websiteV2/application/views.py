from flask import Blueprint
from flask import Flask, render_template, url_for, redirect, request, session, jsonify, flash, Blueprint
import hashlib
from .database import DataBase

from application.encrypt.dh import DiffieHellman

view = Blueprint("views", __name__)


# GLOBAL CONSTANTS
NAME_KEY = 'name'
MSG_LIMIT = 20
PW_SALT = '7f6ZHW%@D6BrBP'

# VIEWS


@view.route("/login", methods=["POST", "GET"])
def login():
    """
    displays main login page and handles saving name in session
    :exception POST
    :return: None
    """
    dh = DiffieHellman()
    db = DataBase()

    if request.method == "POST":  # if user input a name
        name = request.form["inputName"]
        pw = request.form["inputPW"]

        # salf+hash user input
        pw = pw + PW_SALT
        hashedpw = hashlib.sha256(pw.encode()).hexdigest()

        # if user input userid and pw is correct
        if db.verify_user(name, hashedpw):

            session[NAME_KEY] = name
            flash(f'You were successfully logged in as {name}.')

            # generating keys for DH

            private_key, public_key = dh.get_private_key(), dh.generate_public_key()

            # insert keys into db
            db.save_keys(name, public_key, private_key)
            db.get_all_keys()

            return redirect(url_for("views.home"))
        else:
            flash("1Please check your username and password.")

    return render_template("login.html", **{"session": session})


@view.route("/signup", methods=["POST", "GET"])
def signup():
    """
    displays the signup page and sends
    :exception POST
    :return: None
    """

    db = DataBase()

    if request.method == "POST":  # if user input a name
        name = request.form["inputName"]
        pw = request.form["inputPW"]

        if len(name) >= 2:
            if db.username_taken(name):
                pw = pw + PW_SALT
                hashedpw = hashlib.sha256(pw.encode()).hexdigest()
                db.create_user(name, hashedpw)
                flash(f'1The account, {name} has been created.')
            else:
                flash("1Username has already been taken.")
        else:
            flash("1Name must be longer than 1 character.")

    return render_template("signup.html")


@view.route("/logout")
def logout():
    """
    logs the user out by popping name from session
    :return: None
    """
    session.pop(NAME_KEY, None)
    flash("0You were logged out.")
    return redirect(url_for("views.login"))


@view.route("/")
@view.route("/home")
def home():
    """
    displays home page if logged in
    :return: None
    """
    if NAME_KEY not in session:
        return redirect(url_for("views.login"))

    return render_template("index.html", **{"session": session})


@view.route("/history")
def history():
    if NAME_KEY not in session:
        flash("0Please login before viewing message history")
        return redirect(url_for("views.login"))

    json_messages = get_history(session[NAME_KEY])
    print(json_messages)
    return render_template("history.html", **{"history": json_messages})


@view.route("/get_name")
def get_name():
    """
    :return: a json object storing name of logged in user
    """
    data = {"name": ""}
    if NAME_KEY in session:
        data = {"name": session[NAME_KEY]}
    return jsonify(data)


@view.route("/get_messages")
def get_messages():
    """
    :return: all messages stored in database
    """
    db = DataBase()
    msgs = db.get_all_messages(MSG_LIMIT)
    messages = remove_seconds_from_messages(msgs)

    return jsonify(messages)


@view.route("/get_history")
def get_history(name):
    """
    :param name: str
    :return: all messages by name of user
    """
    db = DataBase()
    msgs = db.get_messages_by_name(name)
    messages = remove_seconds_from_messages(msgs)

    return messages


@view.route("/generate-keys", methods=["GET"])
def generate_keys():
    dh = DiffieHellman()
    private_key, public_key = dh.get_private_key(), dh.generate_public_key()
    return jsonify({"private_key": private_key, "public_key": public_key, })


@view.route("/generate-shared-key", methods=["GET"])
def generate_shared_key():
    try:
        local_private_key = request.args.get("local_private_key")
        remote_public_key = request.args.get("remote_public_key")
        print(local_private_key)
        print(remote_public_key)
        shared_key = DiffieHellman.generate_shared_key_static(
            local_private_key, remote_public_key
        )
    except:
        return jsonify({"message": "Invalid public key"}), 400
    return jsonify({"shared_key": shared_key})


# UTILITIES
def remove_seconds_from_messages(msgs):
    """
    removes the seconds from all messages
    :param msgs: list
    :return: list
    """
    messages = []
    for msg in msgs:
        message = msg
        message["time"] = remove_seconds(message["time"])
        messages.append(message)

    return messages


def remove_seconds(msg):
    """
    :return: string with seconds trimmed off
    """
    return msg.split(".")[0][:-3]
