from varonis_saas_core.mappers import BaseMapper, ThreatModelMapper

def test_base_mapper():
    response = {"columns": ["x", "y"], "rows": [[1, 2]]}
    records = BaseMapper().map(response)
    assert records == [{"x": 1, "y": 2}]

def test_threat_model_mapper():
    enum = [{"dataField": "1", "displayField": "Rule A"}]
    mapped = ThreatModelMapper().map(enum)
    assert mapped == [{"id": "1", "name": "Rule A"}]
