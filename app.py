import os
from io import BytesIO

import cv2
import numpy as np
from flask import Flask, jsonify, render_template, request, send_file

try:
    from .stegano_utils import (
        calculate_capacity,
        get_safe_pixel_indices,
        hide_message,
        reveal_message,
    )
except ImportError:
    from stegano_utils import (
        calculate_capacity,
        get_safe_pixel_indices,
        hide_message,
        reveal_message,
    )

app = Flask(__name__)

# ---------------- HOME ----------------
@app.route('/')
def index():
    return render_template('index.html')

# ---------------- ENCRYPT ----------------
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        try:
            file = request.files.get('image')
            if not file:
                return render_template("error.html", error_message="No image selected.")

            image = cv2.imdecode(
                np.frombuffer(file.read(), np.uint8),
                cv2.IMREAD_COLOR
            )

            message = request.form.get('message')
            password = request.form.get('password')

            if not message or not password:
                return render_template(
                    "error.html",
                    error_message="Message and password are required."
                )

            encrypted_image = hide_message(image, message, password)
            _, buffer = cv2.imencode(".png", encrypted_image)

            return send_file(
                BytesIO(buffer.tobytes()),
                as_attachment=True,
                download_name="encrypted.png",
                mimetype="image/png"
            )

        except Exception as e:
            return render_template("error.html", error_message=str(e))

    return render_template('encrypt.html')

# ---------------- DECRYPT ----------------
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        try:
            file = request.files.get('image')
            password = request.form.get('password')

            image = cv2.imdecode(
                np.frombuffer(file.read(), np.uint8),
                cv2.IMREAD_COLOR
            )

            message = reveal_message(image, password)
            if not message:
                return render_template(
                    "error.html",
                    error_message="Incorrect password or no hidden data found."
                )

            return render_template("result.html", decrypted_text=message)

        except Exception as e:
            return render_template("error.html", error_message=str(e))

    return render_template('decrypt.html')

# ---------------- IMAGE STATS (AJAX) ----------------
@app.route('/image_stats', methods=['POST'])
def image_stats():
    try:
        file = request.files['image']
        password = request.form.get('password', "")

        image = cv2.imdecode(
            np.frombuffer(file.read(), np.uint8),
            cv2.IMREAD_COLOR
        )

        h, w = image.shape[:2]
        total_pixels = h * w

        safe_pixels = get_safe_pixel_indices(image)
        safe_count = len(safe_pixels)
        safe_percent = (safe_count / total_pixels) * 100

        capacity = calculate_capacity(image, password)

        stats = (
            f"EMBEDDING MODE : ADAPTIVE (AES-256-GCM, keyed order)\n"
            f"Image Dimension       : {w} × {h}\n"
            f"Total Pixels          : {total_pixels}\n"
            f"Safest Pixels Selected: {capacity['safe_pixels']}\n"
            f"Safe Pixel Percentage : {safe_percent:.2f}%\n"
            f"Max Storable Characters: {capacity['max_chars']}"
        )

        return jsonify({"stats": stats})

    except Exception as e:
        return jsonify({"error": str(e)})

# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
