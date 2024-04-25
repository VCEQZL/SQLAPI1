import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from waitress import serve

app = Flask(__name__)
CORS(app)  # Allow Cross-Origin Resource Sharing

# Specify absolute paths to the model files
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
TFIDF_VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")
TRAINED_MODEL_PATH = os.path.join(MODEL_DIR, "trained_model.pkl")

# Load the trained model and TF-IDF vectorizer
tfidf_vectorizer = joblib.load(TFIDF_VECTORIZER_PATH)
model = joblib.load(TRAINED_MODEL_PATH)

@app.route('/', methods=['POST'])
def detect_sql_injection_api():
    input_str = request.json.get('input_str')

    # Regular expression for detecting SQL injection patterns
    sql_pattern = re.compile(r".*(\'|\"|;|--|union|truncate|-).*")

    # Check for SQL injection patterns in the input string
    if sql_pattern.match(input_str):
        return jsonify({"is_sql_injection": True, "message": "SQL injection detected"})

    # If no SQL injection patterns are found, use the trained model
    query = tfidf_vectorizer.transform([input_str.lower()])
    prediction = model.predict(query)

    return jsonify({"is_sql_injection": bool(prediction[0]), "message": "SQL injection detected"})

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5009)
