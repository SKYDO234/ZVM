"""Parse rendered HTML, not just HTTP 200: browser repair must not hide broken controls."""
import uuid
import html5lib
import pytest
from extensions import db
from models import Job, OSImage
from tests.conftest import signin
from tests.test_provisioning import fixture_vps


def parsed(response):
    assert response.status_code==200
    parser=html5lib.HTMLParser(namespaceHTMLElements=False)
    root=parser.parse(response.get_data(as_text=True))
    assert not parser.errors,parser.errors[:8]
    for form in root.iter('form'):
        action=form.get('action','')
        assert not any(char in action for char in ('"','<','>',' ')),action
        if form.get('method','get').lower()=='post':
            assert any(node.get('name')=='csrf_token' for node in form.iter('input')),action
    return root


@pytest.mark.parametrize('path',['/','/docs','/login','/register'])
def test_public_pages_are_valid_html_with_valid_form_targets(client,path):
    parsed(client.get(path))


@pytest.mark.parametrize('path',['/dashboard','/vps','/vps/create','/vps/console','/webssh','/profile','/settings','/admin','/docs'])
def test_authenticated_pages_are_valid_html(client,users,path):
    signin(client,'operator@example.test');root=parsed(client.get(path))
    if path=='/admin':
        nodes=[form for form in root.iter('form') if form.get('action')=='/admin/nodes']
        assert len(nodes)==1 and nodes[0].get('class')=='form-stack'
        assert {i.get('name') for i in nodes[0].iter('input')}>={'name','url','token','csrf_token'}


def test_instance_controls_console_and_job_render_valid_forms(client,users):
    instance=fixture_vps(users[0]);signin(client,'operator@example.test')
    parsed(client.get(f'/vps/{instance.id}'));parsed(client.get(f'/vps/{instance.id}/console'))
    parsed(client.get(f'/webssh/{instance.id}'))
    job=Job(id=str(uuid.uuid4()),owner_id=users[0].id,instance_id=instance.id,kind='start',engine='qemu',status='failed')
    db.session.add(job);db.session.commit()
    parsed(client.get(f'/vps/jobs/{job.id}'))


def test_create_without_enabled_images_has_a_clear_disabled_state(client,users):
    for image in db.session.scalars(db.select(OSImage)):image.enabled=False
    db.session.commit();signin(client)
    response=client.get('/vps/create')
    root=parsed(response)
    assert 'No operating system images are enabled' in response.get_data(as_text=True)
    assert any(button.get('disabled') is not None for button in root.iter('button') if 'Review configuration' in ''.join(button.itertext()))
