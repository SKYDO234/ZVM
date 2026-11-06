from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required
from engines import EngineError, engine_for
from extensions import db
from models import Audit, Job, VPS
from routes.vps import owned
from services.resource_monitor import host_metrics, instance_metrics, totals
from services.security import audit

bp = Blueprint('api', __name__, url_prefix='/api')


@bp.get('/metrics')
@login_required
def metrics():
    instances = list(db.session.scalars(db.select(VPS).where(VPS.owner_id == current_user.id)))
    data = [instance_metrics(v) for v in instances]
    return jsonify(host=host_metrics(), instances=data, totals=totals(instances, data))


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


@bp.route('/vps/<ident>/console', methods=['GET', 'POST'])
@login_required
def console(ident):
    vps = owned(ident)
    engine = engine_for(vps.engine, vps.node)
    try:
        if request.method == 'POST':
            if vps.suspended:
                raise EngineError('Console input is disabled for suspended instances.')
            payload = request.get_json(silent=True) or {}
            if not isinstance(payload, dict):
                raise EngineError('Console requests must be JSON objects.')
            text = payload.get('input', '')
            result = engine.console_input(vps.spec(), text)
            # Never log console text: it may contain a guest password.
            audit('console.input', 'Sent guest console input; content intentionally not logged.', instance_id=vps.id)
            db.session.commit()
            return jsonify(result)
        return jsonify(output=engine.console(vps.spec()))
    except EngineError as exc:
        return jsonify(error=str(exc)), 409


@bp.get('/activity')
@login_required
def activity():
    rows = db.session.scalars(db.select(Audit).where(Audit.user_id == current_user.id).order_by(Audit.id.desc()).limit(20))
    return jsonify([{'action': a.action, 'message': a.message, 'at': a.created_at.isoformat() + 'Z'} for a in rows])
