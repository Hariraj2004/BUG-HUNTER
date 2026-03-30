from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from ..models import User, LoginEvent
from ..utils import admin_required, role_required

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users', methods=['GET'])
@jwt_required()
@admin_required()
def get_users():
    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "username": u.username,
        "role": u.role
    } for u in users]), 200

@admin_bp.route('/login-events', methods=['GET'])
@jwt_required()
@role_required(['admin', 'analyst'])
def get_login_events():
    events = LoginEvent.query.order_by(LoginEvent.timestamp.desc()).all()
    
    result = []
    for e in events:
        user = User.query.get(e.user_id)
        result.append({
            "id": e.id,
            "user_id": e.user_id,
            "username": user.username if user else None,
            "ip_address": e.ip_address,
            "mac_address": e.mac_address,
            "user_agent": e.user_agent,
            "timestamp": e.timestamp.isoformat()
        })
    return jsonify(result), 200
