from vulblend.db import init_db, query
from vulblend.services.reporting import generate_json, report_payload
from vulblend.demo_data import seed_demo_data

def test_seed_and_json_report(tmp_path, monkeypatch):
    init_db(); seed_demo_data()
    app = dict(query('select * from applications limit 1')[0])
    scan = dict(query('select * from scan_executions limit 1')[0])
    findings = [dict(row) for row in query('select * from findings limit 2')]
    name, content = generate_json(report_payload(app, scan, findings))
    assert name.endswith('.json')
    assert b'VulnBlend' in content
    assert len(query('select * from reports')) >= 1
