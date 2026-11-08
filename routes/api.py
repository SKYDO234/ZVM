from flask import Blueprint, abort, jsonify
from flask_login import current_user, login_required
from extensions import db
from models import Audit, Job, VPS
from routes.vps import owned
from services.resource_monitor import host_metrics, instance_metrics, totals

bp = Blueprint('api', __name__, url_prefix='/api')


@bp.get('/metrics')
@login_required
def metrics():
    query = db.select(VPS) if current_user.is_admin else db.select(VPS).where(VPS.owner_id == current_user.id)
    instances = list(db.session.scalars(query))
    data = [instance_metrics(v) for v in instances]
    result = {'instances': data, 'totals': totals(instances, data)}
    if current_user.is_admin:
        result['host'] = host_metrics()
    return jsonify(result)


@bp.get('/vps/<ident>/metrics')
@login_required
def vps_metrics(ident):
    return jsonify(instance_metrics(owned(ident)))


@bp.get('/jobs/<ident>')
@login_required
def job(ident):
    item = db.get_or_404(Job, ident)
    if item.owner_id != current_user.id and not current_user.is_admin:
        abort(404)
    return jsonify(id=item.id, status=item.status, message=item.message, instance_id=item.instance_id,
                   exists=db.session.get(VPS, item.instance_id) is not None)


@bp.get('/activity')
@login_required
def activity():
    scope = db.select(VPS.id).where(VPS.owner_id == current_user.id)
    query = db.select(Audit)
    if not current_user.is_admin:
        query = query.where(db.or_(Audit.user_id == current_user.id, Audit.instance_id.in_(scope)))
    rows = db.session.scalars(query.order_by(Audit.id.desc()).limit(20))
    return jsonify([{'action': a.action, 'message': a.message, 'at': a.created_at.isoformat() + 'Z'} for a in rows])
