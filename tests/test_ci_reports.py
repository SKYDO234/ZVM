"""CI diagnostic formatting must retain causes and escape workflow commands."""
import importlib.util
import json
from pathlib import Path


def load_reporter():
    spec=importlib.util.spec_from_file_location('skvm_ci_reporter',Path(__file__).parents[1]/'scripts/report-ci.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def test_annotations_escape_newlines_percent_and_title_delimiters(capsys):
    reporter=load_reporter()
    reporter.annotation('notice','case,with:title','first%\n::error::not another command\r')
    output=capsys.readouterr().out
    assert len(output.splitlines())==1 and 'case%2Cwith%3Atitle' in output
    assert 'first%25%0A::error::not another command%0D' in output


def test_long_trace_keeps_the_root_cause_within_github_annotation_limit(capsys):
    load_reporter().annotation('error','case','start\n'+'x'*20000+'\nROOT_CAUSE: invalid SDK argument')
    output=capsys.readouterr().out
    assert 'ROOT_CAUSE: invalid SDK argument' in output and len(output)<4000 and 'bounded traceback' in output


def test_junit_reports_failures_errors_and_skips_not_a_false_green(tmp_path,capsys):
    path=tmp_path/'results.xml'
    path.write_text('<testsuites><testsuite><testcase name="good"/><testcase name="bad"><failure>ROOT_CAUSE</failure></testcase>'
                    '<testcase name="error"><error>setup failed</error></testcase><testcase name="native"><skipped/></testcase></testsuite></testsuites>')
    load_reporter().report_junit(path)
    output=capsys.readouterr().out
    assert 'ROOT_CAUSE' in output and 'setup failed' in output
    assert '4 cases; 2 failures/errors; 1 skipped' in output


def test_catalog_reports_exact_endpoint_outcomes_and_lifecycle_warnings(tmp_path,capsys):
    path=tmp_path/'catalog.json'
    path.write_text(json.dumps([
        {'id':'good','url':'https://vendor.example/good','verified':True,'error':None,'lifecycle_warning':None},
        {'id':'old','url':'https://vendor.example/old','verified':False,'error':'HTTP 404','lifecycle_warning':'EOL'},
        {'id':'bad','url':'https://vendor.example/bad','verified':False,'error':'TLS failed','lifecycle_warning':None}]))
    load_reporter().report_catalog(path)
    output=capsys.readouterr().out
    assert '::notice title=OS endpoint%3A good' in output
    assert '::warning title=OS endpoint%3A old' in output
    assert '::error title=OS endpoint%3A bad' in output
