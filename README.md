# Sláinte Secure

A secure healthcare records system built for the Security Fundamentals and Development
CA (use case 7: *Secure Healthcare Records*). Patients and doctors can store and share
health records, protected with cryptography for confidentiality, integrity,
authentication and non-repudiation.

## Team

| Member | Feature |
|---|---|
| [Glenn] | Accounts and access: registration, password hashing, login, roles |
| [Filip] | Encrypted records: encrypting records at rest and sharing them securely |
| [Andrew] | Integrity and audit: digital signatures on records and a tamper-evident audit log |

## Tech stack

- Python 3.10 or newer
- Flask (web interface)
- SQLite (built into Python, so nothing extra to install)

## Running it locally

### 1. Clone the repo

```bash
git clone https://github.com/<glenn-47>/slaintesecure.git
cd slaintesecure
```

### 2. Create a virtual environment

A virtual environment (venv) keeps this project's packages separate from everything
else on your machine. Each person makes their own; it is **not** committed to Git.

**macOS / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell)**
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

You'll see `(.venv)` at the start of your terminal prompt when it's active.
Activate it again each time you open a new terminal.

### 3. Install the dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
python run.py
```

Then open http://127.0.0.1:5000 in your browser. Press `Ctrl+C` to stop it.

On first run the app creates an `instance/` folder holding the SQLite database and the
session secret key. It's ignored by Git and must never be committed.

## Adding a new package

Install it with your venv active, then add it to `requirements.txt` with its version
so everyone else gets the same one:

```bash
pip install <package>
pip freeze | grep -i <package>    # shows the exact version to copy in
```

## Project structure

```
slaintesecure/
├── run.py                 # starts the app
├── requirements.txt       # packages everyone needs
└── slainte/
    ├── __init__.py        # builds the Flask app (application factory)
    ├── templates/         # HTML pages
    └── static/            # CSS
```
