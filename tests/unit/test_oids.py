from sangfor_hci.snmp import oids
from simulator.snmp_sim import load_snmprec


def test_root_is_sangfor_acloud():
    assert oids.ROOT == "1.3.6.1.4.1.35047.3.2.1"
    assert oids.HOST_CPU.oid == "1.3.6.1.4.1.35047.3.2.1.2.1.1.0"
    assert oids.HOST_MEMORY.oid == "1.3.6.1.4.1.35047.3.2.1.2.2.1.0"
    assert oids.HOST_DISK.oid == "1.3.6.1.4.1.35047.3.2.1.2.3.1.0"
    assert all(s.ratio for s in (oids.HOST_CPU, oids.HOST_MEMORY, oids.HOST_DISK))


def test_every_oid_exists_in_the_full_simulator_dataset():
    data = load_snmprec("node-a")
    for oid in (oids.SYS_DESCR, oids.SYS_NAME, oids.VERSION, oids.BMC_IPMI_IP, oids.BMC_IPMI_VERSION, oids.BMC_VERSION):
        assert oid in data, oid
    for scalar in (oids.HOST_CPU, oids.HOST_MEMORY, oids.HOST_DISK):
        assert scalar.oid in data, scalar.oid
    for table in oids.TABLES:
        assert f"{table.column_oid(table.name_column)}.1" in data, table.name
        for column in table.columns:
            assert f"{table.column_oid(column.suffix)}.1" in data, column.metric


def test_table_metrics_are_hardware_metrics_with_known_kinds():
    for table in oids.TABLES:
        for column in table.columns:
            assert column.metric.startswith("hw.")
            assert column.kind in ("number", "status", "gb")
