import os
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
    model = flask.request.files["model"]
    with open("model_temp.mdl", "wb") as f:
        f.write(model.read())

    try:
        _ = lief.PE.parse(list(peFile.read()))
    except:
        return flask.render_template("invalid.html")
    
    typeClass = predict.Prediction(peFile.read(), "model_temp.mdl")
    os.remove("model_temp.mdl")
    return flask.render_template("prediction.html", typeClass = typeClass)

if __name__ == "__main__":
    app.run(debug=True)
