CipherX Web
CipherX is a Next.js-based web application designed for generating cryptographic keys and performing AES encryption and decryption. Built with a modern, responsive UI using Tailwind CSS and powered by CryptoJS for cryptographic operations, CipherX provides a user-friendly interface for secure data encryption.
Features

Key Generation: Generate a secure cryptographic key from a user-provided password using PBKDF2 with SHA-256.
AES Encryption/Decryption: Encrypt and decrypt text data using AES in CBC mode with a random IV for enhanced security.
Responsive UI: A sleek, dark-themed interface styled with Tailwind CSS, optimized for both desktop and mobile devices.
Reset Functionality: Clear all input and output fields with a single click.
Error Handling: Robust validation and error messages for invalid inputs or cryptographic failures.
Copyright Notice: Displays a footer with "© 2025 CipherX. All rights reserved."

Project Structure
cipherx-web/
├── pages/
│   ├── index.js              # Main page with UI and cryptographic logic
│   ├── _app.js              # Custom App component for global CSS
├── styles/
│   ├── globals.css          # Tailwind CSS configuration
├── package.json             # Project metadata and dependencies
├── tailwind.config.js       # Tailwind CSS configuration
├── postcss.config.js        # PostCSS configuration for Tailwind
├── public/                  # Static assets (e.g., favicon.ico)
├── README.md                # Project documentation
└── .gitignore               # Git ignore file

Prerequisites

Node.js: Version 16 or higher (recommended for Next.js 13.5.8).
npm: Package manager for installing dependencies.

Setup Instructions

Clone the Repository (if hosted on GitHub):
git clone <repository-url>
cd cipherx-web


Install Dependencies:
npm install


Run the Development Server:
npm run dev


Open http://localhost:3000 in your browser to access the application.


Build for Production (optional):
npm run build
npm run start



Usage

Generate a Key:

Enter a password in the "Enter Key" field (e.g., "password123").
Click "Generate Key" to derive a Base64-encoded key, displayed in the "Generated Key" textarea.
The key is generated using PBKDF2 with SHA-256 and a random salt.


Encrypt Data:

Enter text in the "Enter Data" textarea (e.g., "Hello, World!").
Ensure a key is provided or generated.
Click "Encrypt" to generate ciphertext (format: ivBase64:ciphertext) in the "Ciphertext" textarea.


Decrypt Data:

Ensure the "Ciphertext" field contains the output from encryption.
Use the same key or generated key.
Click "Decrypt" to retrieve the original data in the "Decrypted" textarea.


Reset Fields:

Click "Reset" to clear all fields and reset the status.


Error Handling:

Empty inputs will trigger error messages (e.g., "Error: Data field cannot be empty").
Invalid ciphertext or mismatched keys will show errors like "Decryption failed: Invalid ciphertext format (missing IV)".



Security Notes

Key Generation: Uses PBKDF2 with SHA-256 and a random salt for secure key derivation.
Encryption: Employs AES in CBC mode with a random IV, ensuring secure encryption.
Limitations:
The salt is generated per session and not stored, so keys are not reusable across sessions. For persistent keys, store the salt securely.
For production, consider using AES-GCM for authenticated encryption and serving the app over HTTPS to protect data in transit.


Recommendations:
Avoid using weak passwords for key generation.
Ensure secure storage of generated keys if used outside the application.



Dependencies

crypto-js: ^4.1.1 (for cryptographic operations)
next: 13.5.8 (React framework)
react: 18.2.0 (UI library)
react-dom: 18.2.0 (React DOM rendering)
tailwindcss: ^3.4.1 (CSS framework)
autoprefixer: ^10.4.13 (PostCSS plugin)
postcss: ^8.4.21 (CSS processor)

License
© 2025 CipherX. All rights reserved.
