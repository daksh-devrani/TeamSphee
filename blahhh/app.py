from flask import *

app = Flask(__name__)


@app.route("/")
def hello():
    return "<h1> Hello </h1>"


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # TODO: authentication logic here
        return

    return render_template("home.html")



if __name__ == '__main__':
    app.run(debug=True)