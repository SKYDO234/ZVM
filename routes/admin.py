import re
from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from engines import EngineError, engine_for
from extensions import db
from models import Audit, Job, Node, OSImage, Plan, ProvisionTicket, Setting, User, VPS
from services.image_manager import ImageManager
from services.provisioning import reconcile_job
from services.job_control import cancel_queued, close_power, options as job_options
from services.resource_monitor import instance_metrics
from services.security import admin_required, audit, encrypt, integer, settings, validate_url, locked

bp = Blueprint('admin', __name__, url_prefix='/admin')


ADMIN_PAGES = (
    ('index', 'Admin control', 'shield-check', 'Overview and shortcuts to each operator tool.'),
    ('users', 'Users', 'users', 'Accounts, roles, access and assigned quota plans.'),
    ('instances', 'Instances', 'server', 'Real VPS allocations and per-instance administrative pages.'),
    ('plans', 'Plans', 'layers-3', 'Resource budgets across engines and nodes.'),
    ('nodes', 'External nodes', 'network', 'Verified HTTPS agents and encrypted node credentials.'),
    ('images', 'OS images', 'disc-3', 'The retained OS catalog, checksums and live endpoint checks.'),
    ('configuration', 'Configuration', 'sliders-horizontal', 'Platform policies and conservative engine limits.'),
    ('jobs', 'Jobs', 'workflow', 'Queued, running and completed operation history.'),
    ('recovery', 'Recovery', 'scan-search', 'Inspect blocked work without replaying it or clearing live locks.'),
    ('audit', 'Audit log', 'scroll-text', 'Security history without credentials or capability URLs.'),
)


@bp.app_context_processor
def navigation():
    return {'admin_pages': ADMIN_PAGES}


@bp.get('')
@login_required
@admin_required
def index():
    counts = {name: db.session.scalar(db.select(db.func.count()).select_from(model))
              for name, model in (('users', User), ('instances', VPS), ('plans', Plan), ('nodes', Node))}
    counts['recovery'] = db.session.scalar(db.select(db.func.count()).select_from(Job).where(Job.status == 'uncertain'))
    counts['pending'] = db.session.scalar(db.select(db.func.count()).select_from(Job).where(Job.status.in_(['queued', 'running'])))
    return render_template('admin_dashboard.html', admin_page='index', counts=counts)


@bp.get('/users')
@login_required
@admin_required
def users():
    return render_template('admin/users.html', admin_page='users',
                           users=list(db.session.scalars(db.select(User).order_by(User.id))),
                           plans=list(db.session.scalars(db.select(Plan).order_by(Plan.name))))


@bp.get('/instances')
@login_required
@admin_required
def instances():
    return render_template('admin/instances.html', admin_page='instances',
                           instances=list(db.session.scalars(db.select(VPS).order_by(VPS.created_at.desc()))))


@bp.get('/plans')
@login_required
@admin_required
def plans():
    return render_template('admin/plans.html', admin_page='plans', plans=list(db.session.scalars(db.select(Plan).order_by(Plan.name))))


@bp.get('/nodes')
@login_required
@admin_required
def nodes():
    return render_template('admin/nodes.html', admin_page='nodes', nodes=list(db.session.scalars(db.select(Node).order_by(Node.name))))


@bp.get('/images')
@login_required
@admin_required
def images():
    return render_template('admin/images.html', admin_page='images', images=list(db.session.scalars(db.select(OSImage).order_by(OSImage.name))))


@bp.get('/configuration')
@login_required
@admin_required
def configuration():
    return render_template('admin/configuration.html', admin_page='configuration', settings=settings(),
                           capabilities={'qemu': engine_for('qemu').capabilities(), 'docker': engine_for('docker').capabilities()})


def _job_page(recovery=False):
    query = db.select(Job)
    state = request.args.get('status', 'active' if recovery else 'all')
    if state not in ('all', 'active', 'queued', 'running', 'uncertain', 'completed', 'failed', 'cancelled'):
        abort(400)
    if recovery:
        query = query.where(Job.status.in_(['queued', 'running', 'uncertain']))
    if state == 'active':
        query = query.where(Job.status.in_(['queued', 'running', 'uncertain']))
    elif state != 'all':
        query = query.where(Job.status == state)
    ident = request.args.get('instance', '').strip()
    if ident:
        from services.security import valid_uuid
        try:
            valid_uuid(ident)
        except EngineError:
            abort(400)
        query = query.where(Job.instance_id == ident)
    pagination = db.paginate(query.order_by(Job.created_at.desc()), per_page=25, max_per_page=25, error_out=False)
    return render_template('admin/recovery.html' if recovery else 'admin/jobs.html',
                           admin_page='recovery' if recovery else 'jobs', pagination=pagination,
                           jobs=pagination.items, state=state, instance_filter=ident,
                           job_options={job.id: job_options(job, current_user) for job in pagination.items})


@bp.get('/jobs')
@login_required
@admin_required
def jobs():
    return _job_page()


@bp.get('/recovery')
@login_required
@admin_required
def recovery():
    return _job_page(recovery=True)


@bp.get('/audit', endpoint='audit')
@login_required
@admin_required
def audit_log():
    pagination = db.paginate(db.select(Audit).order_by(Audit.id.desc()), per_page=50, max_per_page=50, error_out=False)
    return render_template('admin/audit.html', admin_page='audit', activity=pagination.items, pagination=pagination)


@bp.get('/instances/<ident>/<section>')
@login_required
@admin_required
def instance_control(ident, section):
    if section not in ('network', 'ownership', 'suspension'):
        abort(404)
    instance = db.get_or_404(VPS, ident)
    return render_template('admin/instance_control.html', admin_page='instances', section=section, vps=instance,
                           metric=instance_metrics(instance),
                           owners=list(db.session.scalars(db.select(User).where(User.enabled.is_(True)).order_by(User.name))))


@bp.post('/settings')
@login_required
@admin_required
def update_settings():
    ranges = {'max_instances_per_user': (1, 50), 'max_ram_mb_per_user': (128, 262144), 'max_vcpus_per_user': (1, 128),
              'max_disk_gb_per_user': (1, 10000), 'max_instance_ram_mb': (512, 262144), 'max_instance_vcpus': (1, 128),
              'max_instance_disk_gb': (8, 10000), 'max_instances_per_node': (1, 100), 'host_storage_reserve_gb': (1, 1000)}
    try:
        updated = {key: integer(request.form.get(key), key.replace('_', ' '), *bounds) for key, bounds in ranges.items()}
        for key in ('registration_enabled', 'qemu_enabled', 'docker_enabled', 'restrict_guest_network'):
            updated[key] = request.form.get(key) == '1'
        for key, value in updated.items():
            row = db.session.get(Setting, key)
            if row:
                row.value = value
            else:
                db.session.add(Setting(key=key, value=value))
        audit('admin.settings', 'Updated application and engine limits.')
        db.session.commit()
        flash('Application settings saved. Existing allocations are not silently changed.', 'success')
    except EngineError as exc:
        db.session.rollback()
        flash(str(exc), 'error')
    return redirect(url_for('admin.configuration'))


@bp.post('/users/<int:ident>')
@login_required
@admin_required
def update_user(ident):
    user = db.get_or_404(User, ident)
    try:
        enabled = request.form.get('enabled') == '1'
        role = request.form.get('role', 'user')
        if role not in ('admin', 'user'):
            raise EngineError('Invalid role.')
        if user.id == current_user.id and (not enabled or role != 'admin'):
            raise EngineError('You cannot disable or demote your current administrator account.')
        plan_id = request.form.get('plan_id')
        plan = db.session.get(Plan, integer(plan_id, 'Plan ID', 1, 2**31 - 1)) if plan_id else None
        if plan_id and not plan:
            raise EngineError('Plan not found.')
        user.enabled, user.role, user.plan = enabled, role, plan
        user.session_version += 1
        audit('admin.user', f'Updated access and quota plan for user #{user.id}.')
        db.session.commit()
        if user.id == current_user.id:
            from flask_login import login_user
            login_user(user)
        flash('User updated. Disabling sign-in does not silently kill their guests; use the instance’s Suspension page explicitly.', 'success')
    except EngineError as exc:
        db.session.rollback()
        flash(str(exc), 'error')
    return redirect(url_for('admin.users'))


@bp.post('/users/<int:ident>/delete')
@login_required
@admin_required
def delete_user(ident):
    user = db.get_or_404(User, ident)
    try:
        with locked('allocation'):
            if user.id == current_user.id:
                raise EngineError('You cannot delete your current administrator account.')
            if request.form.get('confirmation', '').strip().lower() != user.email:
                raise EngineError('Account-deletion confirmation is required.')
            if db.session.scalar(db.select(VPS.id).where(VPS.owner_id == user.id).limit(1)):
                raise EngineError('Delete this user’s instances safely before deleting their account.')
            if db.session.scalar(db.select(Job.id).where(Job.owner_id == user.id, Job.status.in_(['queued', 'running', 'uncertain'])).limit(1)):
                raise EngineError('Resolve this user’s active or uncertain jobs before deleting their account.')
            # Creation/assignment reservations belong to the target owner. Preserve
            # a different administrator actor until their in-flight work completes.
            from services.security import decrypt
            for pending in db.session.scalars(db.select(Job).where(Job.owner_id != user.id, Job.status.in_(['queued', 'running', 'uncertain']))):
                if pending.payload and decrypt(pending.payload).get('actor_id') == user.id:
                    raise EngineError('Resolve operations requested by this administrator for other owners before deleting their account.')
            db.session.execute(db.delete(ProvisionTicket).where(ProvisionTicket.owner_id == user.id))
            db.session.execute(db.delete(Job).where(Job.owner_id == user.id))
            # Preserve security history without dangling foreign keys or a fabricated new actor.
            db.session.execute(db.update(Audit).where(Audit.user_id == user.id).values(user_id=None))
            audit('admin.user_deleted', f'Permanently deleted account #{user.id} after checking its resources and jobs.')
            db.session.delete(user)
            db.session.commit()
            flash('Account deleted. Security audit history was retained and old sessions are invalid.', 'success')
    except EngineError as exc:
        db.session.rollback()
        flash(str(exc), 'error')
    return redirect(url_for('admin.users'))


@bp.post('/plans')
@login_required
@admin_required
def save_plan():
    try:
        ident = request.form.get('id')
        plan = db.get_or_404(Plan, integer(ident, 'Plan ID', 1, 2**31 - 1)) if ident else Plan()
        name = request.form.get('name', '').strip()
        if not 2 <= len(name) <= 80:
            raise EngineError('Plan name must be 2–80 characters.')
        exists = db.session.scalar(db.select(Plan).where(Plan.name == name))
        if exists and exists.id != plan.id:
            raise EngineError('A plan with this name already exists.')
        plan.name = name
        plan.max_instances = integer(request.form.get('max_instances'), 'Instance limit', 1, 50)
        plan.ram_mb = integer(request.form.get('ram_mb'), 'Plan RAM', 128, 262144)
        plan.vcpus = integer(request.form.get('vcpus'), 'Plan vCPU', 1, 128)
        plan.disk_gb = integer(request.form.get('disk_gb'), 'Plan disk', 1, 10000)
        db.session.add(plan)
        audit('admin.plan', f'Saved resource plan {name}.')
        db.session.commit()
        flash('Resource plan saved.', 'success')
    except EngineError as exc:
        db.session.rollback()
        flash(str(exc), 'error')
    return redirect(url_for('admin.plans'))


@bp.post('/images/<ident>')
@login_required
@admin_required
def update_image(ident):
    image = db.get_or_404(OSImage, ident)
    try:
        if request.form.get('action') == 'verify':
            ImageManager().verify(image)
            audit('image.verified', f'Checked the live QCOW2 endpoint for {image.name}.')
            db.session.commit()
            flash('Image URL returned QCOW2 content. The full file is validated before use.', 'success')
        else:
            url = validate_url(request.form.get('qemu_url', '').strip(), settings()['image_hosts'])
            checksum = request.form.get('sha256', '').strip().lower()
            if checksum and not re.fullmatch(r'[0-9a-f]{64}', checksum):
                raise EngineError('SHA256 must be 64 hexadecimal characters.')
            image.qemu_url, image.sha256 = url, checksum or None
            image.enabled = request.form.get('enabled') == '1'
            image.verification = 'unverified'
            image.verified_at = None
            image.verification_message = 'URL or policy changed; verify before using.'
            audit('image.updated', f'Updated {image.name} cloud image configuration.')
            db.session.commit()
            flash('Image configuration saved. Docker references remain restricted to the built-in OS catalog.', 'success')
    except EngineError as exc:
        flash(str(exc), 'error')
    return redirect(url_for('admin.images'))


@bp.post('/nodes')
@login_required
@admin_required
def add_node():
    try:
        name = request.form.get('name', '').strip()
        if not 2 <= len(name) <= 80:
            raise EngineError('Node name must be 2–80 characters.')
        if db.session.scalar(db.select(Node.id).where(Node.name == name)):
            raise EngineError('This node name is already used.')
        url = validate_url(request.form.get('url', '').strip().rstrip('/'), current_app.config['NODE_HOSTS'], public=False)
        from urllib.parse import urlsplit
        if urlsplit(url).path not in ('', '/') or urlsplit(url).query:
            raise EngineError('Use an HTTPS origin without a path or query string.')
        token = request.form.get('token', '').strip()
        if not 32 <= len(token) <= 256 or not re.fullmatch(r'[a-zA-Z0-9_-]+', token):
            raise EngineError('Node tokens must be 32–256 URL-safe random characters.')
        node = Node(name=name, url=url, token_encrypted=encrypt(token))
        # Verify connectivity before registering an apparently usable node.
        engine_for('qemu', node).capabilities()
        db.session.add(node)
        audit('node.added', f'Registered authenticated node {name}.')
        db.session.commit()
        flash('External node connected and authenticated.', 'success')
    except EngineError as exc:
        db.session.rollback()
        flash(str(exc), 'error')
    return redirect(url_for('admin.nodes'))


@bp.post('/nodes/<int:ident>/<action>')
@login_required
@admin_required
def node_action(ident, action):
    node = db.get_or_404(Node, ident)
    try:
        if action == 'check':
            result = engine_for('qemu', node).capabilities()
            flash(f'{node.name}: {result["host"]["ram_available_mb"]} MiB available, {result["host"]["cpu_capacity"]} effective CPUs, {result["host"]["disk_free_gb"]} GiB free; {len(result["instances"])} managed instance records.', 'success')
        elif action == 'rotate':
            from types import SimpleNamespace
            token = request.form.get('token', '').strip()
            if not re.fullmatch(r'[a-zA-Z0-9_-]{32,256}', token):
                raise EngineError('Use a random URL-safe token of 32–256 characters.')
            protected = encrypt(token)
            candidate = SimpleNamespace(url=node.url, token_encrypted=protected, enabled=True)
            engine_for('qemu', candidate).capabilities()
            node.token_encrypted = protected
            audit('node.token_rotated', f'Verified and rotated credentials for node {node.name}.')
            db.session.commit()
            flash('Node token rotated after a successful authenticated check.', 'success')
        elif action == 'toggle':
            node.enabled = not node.enabled
            audit('node.updated', f'Node {node.name} enabled={node.enabled}.')
            db.session.commit()
            flash('Node availability updated. Guests are not implicitly stopped.', 'success')
        else:
            abort(404)
    except EngineError as exc:
        flash(str(exc), 'error')
    return redirect(url_for('admin.nodes'))


@bp.post('/jobs/<ident>/reconcile')
@login_required
@admin_required
def reconcile(ident):
    job = db.get_or_404(Job, ident)
    try:
        reconcile_job(job)
        audit('job.reconciled', f'Reconciled job {job.id} using actual engine state.')
        db.session.commit()
        flash('Job reconciled.', 'success')
    except EngineError as exc:
        db.session.rollback()
        flash(str(exc), 'error')
    return redirect(url_for('vps.job', ident=job.id))


@bp.post('/jobs/<ident>/cancel')
@login_required
@admin_required
def cancel_job(ident):
    job = db.get_or_404(Job, ident)
    try:
        cancel_queued(job, current_user)
        flash('Queued request cancelled before any engine action.', 'success')
    except EngineError as exc:
        db.session.rollback()
        flash(str(exc), 'error')
    return redirect(url_for('vps.job', ident=job.id))


@bp.post('/jobs/<ident>/close-power')
@login_required
@admin_required
def close_power_job(ident):
    job = db.get_or_404(Job, ident)
    try:
        close_power(job, current_user)
        flash('Interrupted power request closed without replaying it. Its original outcome is not reported as success.', 'success')
    except EngineError as exc:
        db.session.rollback()
        flash(str(exc), 'error')
    return redirect(url_for('vps.job', ident=job.id))
