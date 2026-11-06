from datetime import timedelta
from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from engines import EngineError
from extensions import db
from models import Audit, Job, Node, OSImage, ProvisionTicket, VPS
from models.user import utcnow
from services.provisioning import queue_action, queue_create
from services.resource_monitor import host_metrics, instance_metrics
from services.security import decrypt, encrypt, integer, locked, settings, valid_uuid
from services.validation import capacity_check, clean_spec, quota_check, select_node, user_limits

bp = Blueprint('vps', __name__, url_prefix='/vps')


def owned(ident):
    vps = db.get_or_404(VPS, ident)
    if vps.owner_id != current_user.id and not current_user.is_admin:
        abort(404)
    return vps


@bp.get('')
@login_required
def listing():
    q = request.args.get('q', '').strip()[:63]
    query = db.select(VPS).where(VPS.owner_id == current_user.id)
    if q:
        query = query.where(VPS.name.icontains(q, autoescape=True))
    instances = list(db.session.scalars(query.order_by(VPS.created_at.desc())))
    return render_template('myvps.html', instances=instances, metrics={v.id: instance_metrics(v) for v in instances}, q=q)


@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    from engines import engine_for
    if request.method == 'POST':
        try:
            spec, credentials = clean_spec(request.form, current_user.id)
            node = select_node(request.form.get('node_id'))
            with locked('allocation'):
                quota_check(current_user, spec)
                capacity_check(spec, node)
                db.session.execute(db.delete(ProvisionTicket).where(ProvisionTicket.expires_at < utcnow()))
                ticket = ProvisionTicket(owner_id=current_user.id, expires_at=utcnow() + timedelta(minutes=10),
                                         payload=encrypt({'spec': spec, 'credentials': credentials, 'node_id': node.id if node else None}))
                db.session.add(ticket)
                db.session.commit()
            return render_template('confirm_vps.html', spec=spec, ticket=ticket, image=db.session.get(OSImage, spec['os_id']), node=node)
        except EngineError as exc:
            flash(str(exc), 'error')
    return render_template('create_vps.html', images=list(db.session.scalars(db.select(OSImage).where(OSImage.enabled.is_(True)))),
                           nodes=list(db.session.scalars(db.select(Node).where(Node.enabled.is_(True)))), limits=user_limits(current_user),
                           host=host_metrics(), settings=settings(),
                           capabilities={'qemu': engine_for('qemu').capabilities(), 'docker': engine_for('docker').capabilities()})


@bp.post('/provision/<ident>')
@login_required
def provision(ident):
    try:
        valid_uuid(ident)
    except EngineError:
        abort(404)
    with locked('ticket-' + ident):
        ticket = db.get_or_404(ProvisionTicket, ident)
        if ticket.owner_id != current_user.id:
            abort(404)
        if ticket.consumed or ticket.expires_at < utcnow():
            flash('This confirmation has expired or already been submitted. Review a new configuration.', 'error')
            return redirect(url_for('vps.create'))
        data = decrypt(ticket.payload)
        node = db.session.get(Node, data['node_id']) if data['node_id'] else None
        try:
            job = queue_create(current_user, data['spec'], data['credentials'], node)
            ticket.consumed = True
            ticket.payload = encrypt({})
            db.session.commit()
            return redirect(url_for('vps.job', ident=job.id))
        except EngineError as exc:
            flash(str(exc), 'error')
            return redirect(url_for('vps.create'))


@bp.get('/jobs/<ident>')
@login_required
def job(ident):
    item = db.get_or_404(Job, ident)
    if item.owner_id != current_user.id and not current_user.is_admin:
        abort(404)
    return render_template('job.html', job=item, vps=db.session.get(VPS, item.instance_id))


@bp.get('/<ident>')
@login_required
def details(ident):
    vps = owned(ident)
    return render_template('vps_details.html', vps=vps, metric=instance_metrics(vps), image=db.session.get(OSImage, vps.os_id),
                           activity=list(db.session.scalars(db.select(Audit).where(Audit.instance_id == ident).order_by(Audit.id.desc()).limit(25))),
                           images=list(db.session.scalars(db.select(OSImage).where(OSImage.enabled.is_(True)))), settings=settings())


@bp.post('/<ident>/action/<action>')
@login_required
def action(ident, action):
    vps = owned(ident)
    if action in ('suspend', 'unsuspend') and not current_user.is_admin:
        abort(403)
    try:
        extra = {}
        if action == 'resize':
            if vps.engine != 'qemu':
                raise EngineError('Disk resizing is only supported for stopped QEMU VMs.')
            extra['disk_gb'] = integer(request.form.get('disk_gb'), 'New disk capacity', vps.disk_gb + 1, settings()['max_instance_disk_gb'])
        if action == 'reinstall':
            if vps.engine != 'qemu':
                raise EngineError('In-place reinstall is only supported for QEMU.')
            data = dict(request.form)
            data.update(name=vps.name, engine=vps.engine, ram_mb=vps.ram_mb, vcpus=vps.vcpus, disk_gb=vps.disk_gb, ssh_port=vps.ssh_port)
            spec, credentials = clean_spec(data, vps.owner_id)
            spec['id'] = vps.id
            spec['forwards'] = vps.runtime.get('forwards', [])
            extra = {'spec': spec, 'credentials': credentials}
        job = queue_action(current_user, vps, action, extra)
        return redirect(url_for('vps.job', ident=job.id))
    except EngineError as exc:
        flash(str(exc), 'error')
        return redirect(url_for('vps.details', ident=ident))


@bp.get('/console')
@bp.get('/<ident>/console')
@login_required
def console(ident=None):
    instances = list(db.session.scalars(db.select(VPS).where(VPS.owner_id == current_user.id)))
    vps = owned(ident) if ident else (instances[0] if instances else None)
    return render_template('console.html', instances=instances, vps=vps, metric=instance_metrics(vps) if vps else None)
