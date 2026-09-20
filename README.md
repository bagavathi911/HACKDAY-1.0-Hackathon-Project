# Adaptive LSB Steganography Project

This project is a secure web application that hides secret text inside an image using adaptive Least Significant Bit (LSB) steganography. It is built with Python and Flask, and it combines image analysis, password-based key generation, and AES-GCM encryption to make hidden messages harder to detect and harder to decode without the correct password.

The goal is to let users securely embed and recover hidden messages in a practical and easy-to-use interface.

## What this project does

When a user uploads an image, the app:

1. Analyzes the image to find the best pixels for hiding data.
2. Chooses pixels based on visual security features such as edges, variance, and entropy.
3. Encrypts the message using a password-derived key.
4. Embeds the encrypted payload into the image without heavily affecting its appearance.
5. Allows the same password to be used later to extract and decrypt the hidden message.

This makes it useful for demonstrations of steganography, secure message concealment, and educational exploration of image-based data hiding.

## Why this project is interesting

Traditional steganography often hides data in predictable pixel patterns. This project improves that by using:

- adaptive pixel selection instead of simple fixed-position embedding
- a password-driven embedding order
- AES-GCM encryption for the hidden message payload
- a keystream mask so the embedded bits are less obvious to inspection
- a simple web interface for upload, encryption, and decryption

## Main features

- Adaptive LSB embedding based on image structure and texture
- Password-based selection and ordering of safe pixels
- AES-256-GCM encryption for the hidden payload
- Decryption only works with the correct password
- Upload and download workflow through a Flask app
- Works with image files commonly used in local testing and demos
- Deployable on Render with Gunicorn

## Tech stack

- Python
- Flask
- OpenCV
- NumPy
- cryptography
- argon2-cffi

## Project structure

- `project/app.py` – Flask routes and web app logic
- `project/stegano_utils.py` – steganography algorithm, encryption, and extraction routines
- `project/templates/` – HTML files for the user interface
- `project/test_stegano_utils.py` – validation and security checks
- `requirements.txt` – project dependencies
- `render.yaml` – deployment configuration for Render
- `wsgi.py` – WSGI entry point for deployment
- `simulation.txt` – reference notes for the adaptive pixel-selection experiment
- `README.md` – project documentation

## How the hiding process works

The app uses a layered approach:

1. It reads the uploaded image and evaluates pixel quality.
2. It picks the safest pixels based on properties like edge strength and local texture.
3. It derives a secure encryption key from the user password.
4. It encrypts the message and prepares it as binary data.
5. It masks the bit pattern with a password-derived keystream.
6. It writes the bits into the least significant bits of selected pixel channels.

To recover the message, the app recomputes the same safe-pixel order and decrypts the payload using the same password.

## Requirements

Before running the project, make sure you have:

- Python 3.10 or newer
- pip installed
- a virtual environment recommended

## Installation

Clone the project and install the dependencies:

```bash
git clone <your-repository-url>
cd "hackathon project"
python -m venv .venv
```

On Windows:

```bash
.venv\Scripts\activate
pip install -r requirements.txt
```

On macOS/Linux:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the app locally

You can start the app in either of these ways:

### Option 1: Flask CLI

```bash
python -m flask --app project.app run
```

### Option 2: Run the app file directly

```bash
cd project
python app.py
```

Then open the app in your browser:

```text
http://localhost:5000/
```

## How to use it

### Encrypt a message

1. Open the app in the browser.
2. Go to the encryption page.
3. Upload an image.
4. Enter your secret message.
5. Enter a password.
6. Download the generated image containing the hidden message.

### Decrypt a message

1. Upload the encoded image.
2. Enter the same password used during encryption.
3. The app will reveal the hidden message if the password is correct.

## Deployment

This project is set up for deployment on Render.

### Render steps

1. Push the project to GitHub.
2. Create a new Web Service in Render.
3. Connect the repository.
4. Use the project root as the service root.
5. Render will use the included deployment configuration.

The app is configured to run with Gunicorn using a command similar to:

```bash
gunicorn project.app:app --bind 0.0.0.0:$PORT
```

## Important notes

- PNG and BMP images are usually the best choices for this kind of steganography.
- JPEG images may be less reliable because lossy compression can destroy hidden data.
- This project is designed mainly for text-based hidden messages.
- The password is critical: without it, the hidden message cannot be recovered correctly.
- This is intended for educational and research use, not as a production-grade secure messaging system.

## Security and limitations

This project improves on basic LSB steganography by adding:

- encryption of payload data
- password-based pixel ordering
- adaptive pixel selection
- keystream masking

However, it should still be considered a learning project and a prototype. It is useful for understanding steganographic ideas, but it is not designed to replace mature, audited security systems.

## References

- `simulation.txt` contains notes and experiments related to adaptive safe-pixel selection.
- The app implementation applies those ideas in a Flask web interface for practical use.

## License

This project is provided for educational, academic, and demonstration purposes.

