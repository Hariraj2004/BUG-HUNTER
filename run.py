from app import create_app
from app.extensions import db, socketio
from app.models import User
from werkzeug.security import generate_password_hash
import sys

app = create_app()

@app.cli.command("seed-admin")
def seed_admin():
    """Seed the admin user."""
    admin = User.query.filter_by(username='admin').first()
    if admin is None:
        admin = User(username='admin', password_hash=generate_password_hash('Admin@123'), role='admin')
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully.")
    else:
        print("Admin user already exists.")

if __name__ == '__main__':
    socketio.run(app, debug=True, host='127.0.0.1', port=5000)
