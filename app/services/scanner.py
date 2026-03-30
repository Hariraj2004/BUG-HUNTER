import time
import socket
import json
from ..extensions import db, socketio
from ..models import Scan

def run_port_scan(scan_id, target, ports):
    from app import create_app
    app = create_app()
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        results = []
        for port in ports:
            time.sleep(0.5)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            try:
                result = s.connect_ex((target, int(port)))
                if result == 0:
                    results.append({"port": port, "state": "open"})
                else:
                    results.append({"port": port, "state": "closed or filtered"})
            except socket.error:
                results.append({"port": port, "state": "error"})
            finally:
                s.close()

        scan.status = 'completed'
        scan.result = json.dumps(results)
        db.session.commit()
        
        socketio.emit('scan_update', {'scan_id': scan.id, 'status': 'completed', 'result': results}, namespace='/')

def run_subdomain_enum(scan_id, target):
    from app import create_app
    app = create_app()
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        common_prefixes = ['www', 'mail', 'ftp', 'm', 'blog', 'dev', 'api']
        results = []
        
        for prefix in common_prefixes:
            time.sleep(0.3)
            subdomain = f"{prefix}.{target}"
            try:
                ip = socket.gethostbyname(subdomain)
                results.append({"subdomain": subdomain, "ip": ip})
            except socket.gaierror:
                pass
                
        scan.status = 'completed'
        scan.result = json.dumps(results)
        db.session.commit()
        
        socketio.emit('scan_update', {'scan_id': scan.id, 'status': 'completed', 'result': results}, namespace='/')

def run_path_traversal(scan_id, target):
    from app import create_app
    import urllib.request
    import urllib.error
    
    app = create_app()
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        payloads = [
            '../../../etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd'
        ]
        
        results = []
        
        for payload in payloads:
            time.sleep(0.5)
            url = f"http://{target}/{payload}" if not target.startswith('http') else f"{target}/{payload}"
            try:
                req = urllib.request.Request(url, method='GET')
                response = urllib.request.urlopen(req, timeout=2)
                body = response.read().decode('utf-8', errors='ignore')
                if 'root:x:0:0' in body:
                    results.append({"payload": payload, "vulnerable": True})
                else:
                    results.append({"payload": payload, "vulnerable": False})
            except urllib.error.URLError:
                results.append({"payload": payload, "vulnerable": False, "error": "Connection failed"})
            except Exception as e:
                results.append({"payload": payload, "vulnerable": False, "error": str(e)})

        scan.status = 'completed'
        scan.result = json.dumps(results)
        db.session.commit()
        
        socketio.emit('scan_update', {'scan_id': scan.id, 'status': 'completed', 'result': results}, namespace='/')
