from flask import Flask

from api import q1
from api import q2

app = Flask(__name__)

app.register_blueprint(q1.app)
app.register_blueprint(q2.app)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
