from flask import Blueprint, request, jsonify
from ..services.argus_service import ArgusService

argus_bp = Blueprint("argus", __name__)
argus_service = ArgusService()


@argus_bp.route("/modules", methods=["GET"])
def list_modules():
    """Returns all supported modules grouped by section."""
    return jsonify({
        "success": True,
        "modules": argus_service.list_modules()
    })


@argus_bp.route("/scan", methods=["POST"])
def start_scan():
    """Generic scan endpoint — accepts any module_id."""
    data = request.get_json() or {}
    target = data.get("target")
    module_id = data.get("module_id")

    if not target:
        return jsonify({"success": False, "message": "target is required"}), 400
    if module_id is None:
        return jsonify({"success": False, "message": "module_id is required"}), 400

    try:
        module_id = int(module_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "module_id must be an integer"}), 400

    mod = argus_service.get_module(module_id)
    if not mod:
        return jsonify({"success": False, "message": f"Module {module_id} not found"}), 404

    try:
        job = argus_service.start_scan(module_id, target)
        return jsonify({"success": True, "job": job}), 202
    except ValueError as e:
        return jsonify({"success": False, "message": str(e)}), 400


@argus_bp.route("/jobs", methods=["GET"])
def get_jobs():
    return jsonify({
        "success": True,
        "jobs": argus_service.get_all_jobs()
    })


@argus_bp.route("/jobs/<job_id>", methods=["GET"])
def get_job(job_id):
    job = argus_service.get_job(job_id)
    if not job:
        return jsonify({"success": False, "message": "job not found"}), 404
    return jsonify({"success": True, "job": job})
