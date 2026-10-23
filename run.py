"""
Entry point for Sláinte Secure.

Run with:  python run.py
Then open: http://127.0.0.1:5000
"""

from slainte import create_app

app = create_app()

if __name__ == "__main__":
    # debug=True gives auto-reload and detailed error pages while developing.
    # It must be turned off for anything other than local development,
    # because the debugger lets anyone viewing an error page run code.
    # host="127.0.0.1" keeps the app reachable from this laptop only.
    app.run(host="127.0.0.1", port=5000, debug=True)
