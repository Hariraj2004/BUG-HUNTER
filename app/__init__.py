from flask import Flask, jsonify, render_template
from .extensions import db, jwt, socketio
from .config import Config
from flask_cors import CORS

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    CORS(app)
    db.init_app(app)
    jwt.init_app(app)
    socketio.init_app(app)

    # Root route to serve the dashboard
    @app.route('/')
    def index():
        return render_template('dashboard.html')

    # API health-check route
    @app.route('/api/health')
    def health_check():
        return jsonify({
            'status': 'online',
            'service': 'Bounty-Hunter API',
            'endpoints': {
                'auth': '/api/auth',
                'scans': '/api/scans',
                'admin': '/api/admin',
                'argus': '/api/argus'
            }
        })

    # Register blueprints
    from .auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    
    from .routes.scans import scans_bp
    app.register_blueprint(scans_bp, url_prefix='/api/scans')
    
    from .routes.admin import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/api/admin')

    from .routes.argus import argus_bp
    app.register_blueprint(argus_bp, url_prefix='/api/argus')

    return app
