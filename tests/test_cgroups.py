"""Kernel topology fixtures are plain temporary files, never real controller writes."""
from types import SimpleNamespace
import pytest
from engines import EngineError
from services.cgroups import Snapshot, cpu_set_count, inspect
from services.resource_monitor import host_metrics, require_known_capacity


def topology(tmp_path, members, mounts):
    member=tmp_path/'membership';member.write_text(members)
    mountinfo=tmp_path/'mountinfo';mountinfo.write_text(mounts)
    return member,mountinfo


def put(directory, **values):
    directory.mkdir(parents=True,exist_ok=True)
    for name,value in values.items():
        (directory/name.replace('__','.')).write_text(str(value))


def test_v2_leaf_limit_is_not_hidden_by_unlimited_mount_root(tmp_path):
    root=tmp_path/'cg';leaf=root/'team'/'panel'
    put(root,memory__max='max',memory__current=9000,cpu__max='max 100000',cpuset__cpus__effective='0-7')
    put(root/'team',memory__max=8000,memory__current=7000,cpu__max='150000 100000')
    put(leaf,memory__max=4000,memory__current=1000,cpu__max='max 100000',cpu__stat='usage_usec 2500000\n',cpuset__cpus__effective='0-3')
    args=topology(tmp_path,'0::/team/panel\n',f'1 0 0:1 / {root} rw - cgroup2 cgroup rw\n')
    result=inspect(*args)
    assert result.memory_limit==4000 and result.memory_usage==1000
    assert result.memory_available==1000  # Parent/sibling pressure, not leaf's apparent 3000 free.
    assert result.cpu_limit==1.5 and result.read_cpu_seconds()==2.5
    assert not result.errors


def test_v1_memory_cpu_cpuacct_and_cpuset_are_honored(tmp_path):
    memory,cpu,cpuset=[tmp_path/name for name in ('memory','cpu,cpuacct','cpuset')]
    for root in (memory,cpu,cpuset):root.mkdir()
    put(memory,memory__limit_in_bytes=10000,memory__usage_in_bytes=6000)
    put(memory/'job',memory__limit_in_bytes=5000,memory__usage_in_bytes=2000)
    put(cpu,cpu__cfs_quota_us=100000,cpu__cfs_period_us=100000)
    put(cpu/'job',cpu__cfs_quota_us=50000,cpu__cfs_period_us=100000,cpuacct__usage=1200000000)
    put(cpuset,cpuset__cpus='0-3');put(cpuset/'job',cpuset__cpus='')
    members='5:memory:/job\n4:cpu,cpuacct:/job\n3:cpuset:/job\n'
    mounts=f'1 0 0:1 / {memory} rw - cgroup cgroup rw,memory\n2 0 0:2 / {cpu} rw - cgroup cgroup rw,cpu,cpuacct\n3 0 0:3 / {cpuset} rw - cgroup cgroup rw,cpuset\n'
    result=inspect(*topology(tmp_path,members,mounts))
    assert result.memory_limit==5000 and result.memory_available==3000
    assert result.cpu_limit==.5 and result.read_cpu_seconds()==1.2
    assert not result.errors


def test_mount_root_and_escaped_mountpoint_map_membership(tmp_path):
    root=tmp_path/'with space';put(root,memory__max=1000,memory__current=10,cpu__max='max 100000')
    put(root/'child',memory__max=500,memory__current=100,cpu__max='200000 100000')
    escaped=str(root).replace(' ','\\040')
    result=inspect(*topology(tmp_path,'0::/tenant/child\n',f'1 0 0:1 /tenant {escaped} rw - cgroup2 cgroup rw\n'))
    assert result.memory_limit==500 and result.memory_available==400 and not result.errors


def test_cgroup_namespace_root_mapping(tmp_path):
    root=tmp_path/'cg';put(root,memory__max=1000,memory__current=400)
    result=inspect(*topology(tmp_path,'0::/\n',f'1 0 0:1 /outside/namespace {root} rw - cgroup2 cgroup rw\n'))
    assert result.memory_limit==1000 and result.memory_available==600 and not result.errors


@pytest.mark.parametrize('quota',['broken','100000 0','oops 100000'])
def test_invalid_quota_fails_closed_instead_of_guessing_host_capacity(tmp_path,quota):
    root=tmp_path/'cg';put(root,cpu__max=quota)
    result=inspect(*topology(tmp_path,'0::/\n',f'1 0 0:1 / {root} rw - cgroup2 cgroup rw\n'))
    assert result.errors
    with pytest.raises(EngineError,match='cannot be verified'):
        require_known_capacity({'capacity_known':False,'capacity_reason':' '.join(result.errors)})


def test_unmappable_membership_does_not_escape_mount(tmp_path):
    root=tmp_path/'cg';put(root,memory__max=1)
    result=inspect(*topology(tmp_path,'0::/../../outside\n',f'1 0 0:1 / {root} rw - cgroup2 cgroup rw\n'))
    assert result.memory_limit is None and result.errors


@pytest.mark.parametrize('text,count',[('0-3,6,8-9',7),('0-3,2-5',6),('0-999999999',1000000000)])
def test_cpu_set_ranges_are_counted_without_expansion(text,count):
    assert cpu_set_count(text)==count


def test_missing_topology_is_not_reported_as_known_capacity(tmp_path):
    result=inspect(tmp_path/'absent',tmp_path/'also-absent')
    assert result.errors


def test_host_metrics_keep_actual_cgroup_usage_separate_from_parent_pressure(app,monkeypatch):
    mib=2**20
    snapshot=Snapshot(memory_limit=1024*mib,memory_available=100*mib,memory_usage=256*mib,cpu_limit=1.999)
    monkeypatch.setattr('services.resource_monitor.cgroup_snapshot',lambda:snapshot)
    monkeypatch.setattr('services.resource_monitor.psutil.virtual_memory',lambda:SimpleNamespace(total=8192*mib,available=4096*mib))
    result=host_metrics()
    assert result['ram_total_mb']==1024 and result['ram_available_mb']==100
    assert result['ram_used_mb']==256 and result['ram_percent']==25
    assert result['cpu_capacity']<=1.99 and result['memory_scope']=='cgroup'
