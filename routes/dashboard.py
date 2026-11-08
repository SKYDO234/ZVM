from flask import Blueprint, redirect, render_template, url_for
from flask_login import current_user, login_required
from extensions import db
from models import Audit, Job, Node, VPS
from engines import engine_for
from services.resource_monitor import host_metrics, instance_metrics, totals
from services.security import settings
from services.validation import user_limits

bp = Blueprint('dashboard', __name__)


@bp.get('/')
def starter():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index' if current_user.is_admin else 'dashboard.user_index'))
    return render_template('starter.html')


@bp.get('/dashboard')
@login_required
def index():
    if not current_user.is_admin:
        return user_index()  # Safe compatibility URL; never render admin data for a user.
    instances = list(db.session.scalars(db.select(VPS).order_by(VPS.created_at.desc())))
    metrics = [instance_metrics(v) for v in instances]
    activity = list(db.session.scalars(db.select(Audit).where(Audit.user_id == current_user.id).order_by(Audit.id.desc()).limit(6)))
    jobs = list(db.session.scalars(db.select(Job).where(Job.owner_id == current_user.id).order_by(Job.created_at.desc()).limit(5)))
    return render_template('dashboard.html', instances=instances[:4], metrics={m['id']: m for m in metrics},
                           totals=totals(instances, metrics), activity=activity, jobs=jobs,
                           host=host_metrics(), capabilities={'qemu': engine_for('qemu').capabilities(), 'docker': engine_for('docker').capabilities()},
                           limits=user_limits(current_user), nodes=list(db.session.scalars(db.select(Node).where(Node.enabled.is_(True)))))


@bp.get('/user')
@login_required
def user_index():
    instances = list(db.session.scalars(db.select(VPS).where(VPS.owner_id == current_user.id).order_by(VPS.created_at.desc())))
    measured = [instance_metrics(v) for v in instances]
    scope = db.select(VPS.id).where(VPS.owner_id == current_user.id)
    activity = list(db.session.scalars(db.select(Audit).where(db.or_(Audit.user_id == current_user.id, Audit.instance_id.in_(scope)))
                                       .order_by(Audit.id.desc()).limit(8)))
    jobs = list(db.session.scalars(db.select(Job).where(Job.owner_id == current_user.id).order_by(Job.created_at.desc()).limit(5)))
    return render_template('user_dashboard.html', instances=instances, metrics={m['id']: m for m in measured},
                           totals=totals(instances, measured), limits=user_limits(current_user), activity=activity, jobs=jobs)


@bp.get('/settings')
@login_required
def preferences():
    if not current_user.is_admin:
        return render_template('user_settings.html', limits=user_limits(current_user))
    return render_template('settings.html', host=host_metrics(), settings=settings(), limits=user_limits(current_user),
                           capabilities={'qemu': engine_for('qemu').capabilities(), 'docker': engine_for('docker').capabilities()},
                           nodes=list(db.session.scalars(db.select(Node).where(Node.enabled.is_(True)))))


@bp.get('/docs')
def docs():
    return render_template('docs.html')
