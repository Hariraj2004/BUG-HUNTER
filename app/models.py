from datetime import datetime
from .extensions import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user') # admin, analyst, user
    login_events = db.relationship('LoginEvent', backref='user', lazy=True)
    scans = db.relationship('Scan', backref='user', lazy=True)

class LoginEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(50))
    mac_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False) # port-scan, subdomain-enum, path-traversal
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending') # pending, running, completed, failed
    result = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ArgusJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    result = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
