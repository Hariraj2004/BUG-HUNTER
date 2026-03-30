from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models import Scan, User
from ..extensions import db, socketio
from ..services.scanner import run_port_scan, run_subdomain_enum, run_path_traversal
from ..utils import role_required
import threading

scans_bp = Blueprint('scans', __name__)

@scans_bp.route('/port-scan', methods=['POST'])
@jwt_required()
def port_scan():
    data = request.get_json()
    if not data:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    target = data.get('target')
    ports = data.get('ports', [22, 80, 443, 8080])

    if not target:
        return jsonify({"msg": "Target is required"}), 400

    current_user_id = get_jwt_identity()

    scan = Scan(
        user_id=current_user_id,
        scan_type='port-scan',
        target=target,
        status='running'
    )
    db.session.add(scan)
    db.session.commit()
    
    socketio.emit('scan_update', {'scan_id': scan.id, 'status': 'running'}, namespace='/')

    # Run scan in background
    thread = threading.Thread(target=run_port_scan, args=(scan.id, target, ports))
    thread.daemon = True
    thread.start()

    return jsonify({"msg": "Port scan started", "scan_id": scan.id}), 202

@scans_bp.route('/subdomain-enum', methods=['POST'])
@jwt_required()
def subdomain_enum():
    data = request.get_json()
    if not data:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    target = data.get('target')

    if not target:
        return jsonify({"msg": "Target is required"}), 400

    current_user_id = get_jwt_identity()

    scan = Scan(
        user_id=current_user_id,
        scan_type='subdomain-enum',
        target=target,
        status='running'
    )
    db.session.add(scan)
    db.session.commit()

    socketio.emit('scan_update', {'scan_id': scan.id, 'status': 'running'}, namespace='/')

    thread = threading.Thread(target=run_subdomain_enum, args=(scan.id, target))
    thread.daemon = True
    thread.start()

    return jsonify({"msg": "Subdomain enum started", "scan_id": scan.id}), 202

@scans_bp.route('/path-traversal', methods=['POST'])
@jwt_required()
def path_traversal():
    data = request.get_json()
    if not data:
        return jsonify({"msg": "Missing JSON in request"}), 400
        
    target = data.get('target')

    if not target:
        return jsonify({"msg": "Target is required"}), 400

    current_user_id = get_jwt_identity()

    scan = Scan(
        user_id=current_user_id,
        scan_type='path-traversal',
        target=target,
        status='running'
    )
    db.session.add(scan)
    db.session.commit()

    socketio.emit('scan_update', {'scan_id': scan.id, 'status': 'running'}, namespace='/')

    thread = threading.Thread(target=run_path_traversal, args=(scan.id, target))
    thread.daemon = True
    thread.start()

    return jsonify({"msg": "Path traversal scan started", "scan_id": scan.id}), 202

@scans_bp.route('', methods=['GET'])
@jwt_required()
def get_user_scans():
    current_user_id = get_jwt_identity()
    user_scans = Scan.query.filter_by(user_id=current_user_id).order_by(Scan.timestamp.desc()).all()
    return jsonify([{
        "id": s.id,
        "scan_type": s.scan_type,
        "target": s.target,
        "status": s.status,
        "timestamp": s.timestamp.isoformat()
    } for s in user_scans]), 200

@scans_bp.route('/<int:scan_id>', methods=['GET'])
@jwt_required()
def get_scan(scan_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    scan = Scan.query.get(scan_id)

    if not scan:
        return jsonify({"msg": "Scan not found"}), 404
        
    if user.role not in ['admin', 'analyst'] and scan.user_id != current_user_id:
        return jsonify({"msg": "Access denied"}), 403

    return jsonify({
        "id": scan.id,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "status": scan.status,
        "result": scan.result,
        "timestamp": scan.timestamp.isoformat()
    }), 200

@scans_bp.route('/all', methods=['GET'])
@jwt_required()
@role_required(['admin', 'analyst'])
def get_all_scans():
    all_scans = Scan.query.order_by(Scan.timestamp.desc()).all()
    return jsonify([{
        "id": s.id,
        "user_id": s.user_id,
        "scan_type": s.scan_type,
        "target": s.target,
        "status": s.status,
        "timestamp": s.timestamp.isoformat()
    } for s in all_scans]), 200
