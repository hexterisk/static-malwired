import lief
import flask

import predict

app = flask.Flask(__name__)

@app.route('/')
def index():
    return flask.render_template("index.html")

@app.route("/uploader", methods = ["POST"])
def upload_file():
    peFile = flask.request.files["pe"]
    try:
        _ = lief.PE.parse(list(peFile.read()))
    except:
        return flask.render_template("invalid.html")
    
    mal_class = predict.Prediction(peFile.read())
    return flask.render_template("prediction.html", mal_class = mal_class)

if __name__ == "__main__":
    app.run(debug=True)
