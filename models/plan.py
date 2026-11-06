from extensions import db


class Plan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    max_instances = db.Column(db.Integer, nullable=False)
    ram_mb = db.Column(db.Integer, nullable=False)
    vcpus = db.Column(db.Integer, nullable=False)
    disk_gb = db.Column(db.Integer, nullable=False)
