from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def home():
    return "Home page works!"

@app.route('/test')
def test():
    return jsonify({'status': 'SUCCESS', 'message': 'Test route working!'})

if __name__ == '__main__':
    print("Starting test Flask app...")
    app.run(debug=True, port=5001, use_reloader=False)
