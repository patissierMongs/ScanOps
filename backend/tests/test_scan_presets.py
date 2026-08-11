"""스캔 프리셋 — 파일 형식, 도킹 동기화 API, 단독 스캐너와의 어휘 동일성.

프리셋은 웹 서버와 단독 스캐너 **양쪽 파일**에 같은 내용으로 존재해야 의미가 있다.
그래서 이 파일은 세 가지를 함께 지킨다.
1) 프리셋 문서 형식과 충돌 판정 규칙
2) /api/scan-presets 의 권한·병합·충돌 계약
3) 단독 스캐너의 옵션 키 → nmap 플래그 표가 웹 레지스트리와 한 글자도 다르지 않을 것
   (다르면 같은 프리셋이 두 곳에서 서로 다른 스캔이 된다)
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from scanops.config import get_settings
from scanops.scanning import preset_store, scan_options

from .conftest import make_user, token_for

SCANNER = Path(__file__).resolve().parents[2] / "scanner" / "scanops_scanner.py"


def _load_scanner():
    spec = importlib.util.spec_from_file_location("scanops_standalone_for_presets", SCANNER)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _auth(client, role="auditor"):
    make_user(f"preset_{role}", "Preset-pass-1234", role)
    return {"Authorization": "Bearer " + token_for(client, f"preset_{role}", "Preset-pass-1234")}


def _preset(name, **kw):
    base = {"name": name, "workflow": "single", "options": ["syn", "version"],
            "ports": "22,443", "nse": ["ssl-cert"]}
    base.update(kw)
    return base


@pytest.fixture(autouse=True)
def _clean_preset_file():
    get_settings().preset_file.unlink(missing_ok=True)
    yield
    get_settings().preset_file.unlink(missing_ok=True)


# ── 문서 형식 ──

def test_preset_rejects_values_outside_the_option_and_script_whitelists():
    with pytest.raises(ValueError):
        preset_store.normalize_preset(_preset("x", options=["syn", "--dangerous"]))
    with pytest.raises(ValueError):
        preset_store.normalize_preset(_preset("x", nse=["rm -rf"]))
    with pytest.raises(ValueError):
        preset_store.normalize_preset(_preset("x", ports="22;80"))
    with pytest.raises(ValueError):
        preset_store.normalize_preset(_preset("x", workflow="whatever"))
    with pytest.raises(ValueError):
        preset_store.normalize_preset(_preset("   "))


def test_option_order_and_metadata_do_not_change_a_preset_identity():
    """선택 순서·설명·저장 시각이 달라도 같은 스캔이면 같은 프리셋으로 본다.

    이 규칙이 없으면 웹에서 체크박스를 누른 순서만 달라도 동기화가 충돌로 막힌다.
    """
    a = preset_store.normalize_preset(_preset("weekly", options=["version", "syn"]))
    b = preset_store.normalize_preset(
        _preset("weekly", options=["syn", "version"], description="주간", updated_at="2020-01-01T00:00:00Z"),
    )
    assert preset_store.fingerprint(a) == preset_store.fingerprint(b)
    assert a["options"] == b["options"]


def test_duplicate_names_are_rejected_regardless_of_case_and_spacing():
    with pytest.raises(ValueError):
        preset_store.normalize_presets([_preset("Weekly Full"), _preset("  weekly   full ")])


def test_conflict_is_same_name_with_different_scan_behaviour():
    local = preset_store.normalize_presets([_preset("shared", ports="22"), _preset("only-local")])
    remote = preset_store.normalize_presets([_preset("shared", ports="443"), _preset("only-remote")])
    delta = preset_store.diff(local, remote)
    assert [c["name"] for c in delta["conflicts"]] == ["shared"]
    assert [p["name"] for p in delta["only_local"]] == ["only-local"]
    assert [p["name"] for p in delta["only_remote"]] == ["only-remote"]

    same = preset_store.normalize_presets([_preset("shared"), _preset("only-remote")])
    merged = preset_store.merge(preset_store.normalize_presets([_preset("shared"), _preset("only-local")]), same)
    assert [p["name"] for p in merged] == ["only-local", "only-remote", "shared"]


def test_saved_file_survives_a_reload_unchanged(tmp_path):
    path = tmp_path / "scan_presets.json"
    saved = preset_store.save(path, [_preset("weekly"), _preset("adhoc", workflow="auto")])
    assert preset_store.load(path) == saved


def test_newer_schema_file_is_refused_instead_of_silently_downgraded(tmp_path):
    path = tmp_path / "scan_presets.json"
    path.write_text(json.dumps({"schema": preset_store.PRESET_SCHEMA + 1, "presets": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        preset_store.load(path)


# ── API 계약 ──

def test_viewer_can_read_presets_but_not_write(client):
    viewer = _auth(client, "viewer")
    empty = client.get("/api/scan-presets", headers=viewer).json()
    assert empty["schema"] == 1 and empty["presets"] == []
    assert client.put("/api/scan-presets", headers=viewer,
                      json={"revision": empty["revision"], "presets": [_preset("x")]}).status_code == 403
    assert client.put("/api/scan-presets/item/x", headers=viewer, json=_preset("x")).status_code == 403
    assert client.delete("/api/scan-presets/item/x", headers=viewer).status_code == 403
    assert client.post("/api/scan-presets/sync", headers=viewer, json={"presets": []}).status_code == 403


def test_presets_persist_to_the_server_file_and_come_back(client):
    auth = _auth(client)
    r = client.put("/api/scan-presets/item/weekly", headers=auth, json=_preset("weekly"))
    assert r.status_code == 200, r.text
    assert [p["name"] for p in r.json()["presets"]] == ["weekly"]
    assert get_settings().preset_file.exists()
    assert [p["name"] for p in client.get("/api/scan-presets", headers=auth).json()["presets"]] == ["weekly"]


def test_saving_one_preset_never_drops_presets_the_client_had_not_read(client):
    """lost update 회귀: 목록을 읽은 뒤 다른 곳에서 추가된 항목이 저장으로 사라지면 안 된다.

    웹 화면이 빈 목록을 읽고 있는 동안 단독 스캐너 동기화가 프리셋을 넣는 상황이다.
    """
    auth = _auth(client)
    assert client.get("/api/scan-presets", headers=auth).json()["presets"] == []   # 화면이 읽은 시점
    client.post("/api/scan-presets/sync", headers=auth, json={"presets": [_preset("from-scanner")]})

    r = client.put("/api/scan-presets/item/from-web", headers=auth, json=_preset("from-web"))
    assert r.status_code == 200, r.text
    assert [p["name"] for p in r.json()["presets"]] == ["from-scanner", "from-web"]


def test_whole_list_replacement_is_refused_when_the_document_moved(client):
    """전체 교체는 '내가 읽은 것이 전부였다'는 주장이다 — 사실이 아니면 409."""
    auth = _auth(client)
    stale = client.get("/api/scan-presets", headers=auth).json()["revision"]
    client.put("/api/scan-presets/item/from-scanner", headers=auth, json=_preset("from-scanner"))

    r = client.put("/api/scan-presets", headers=auth,
                   json={"revision": stale, "presets": [_preset("from-web")]})
    assert r.status_code == 409, r.text
    assert [p["name"] for p in client.get("/api/scan-presets", headers=auth).json()["presets"]] \
        == ["from-scanner"]

    fresh = client.get("/api/scan-presets", headers=auth).json()["revision"]
    ok = client.put("/api/scan-presets", headers=auth,
                    json={"revision": fresh, "presets": [_preset("from-web")]})
    assert ok.status_code == 200, ok.text
    assert [p["name"] for p in ok.json()["presets"]] == ["from-web"]


def test_metadata_only_edits_still_invalidate_a_stale_whole_list_replace(client):
    """revision 은 '이 쓰기가 파괴할 수 있는 모든 것'을 덮어야 한다.

    fingerprint 는 '같은 스캔인가'를 묻는 값이라 description 을 일부러 뺀다. revision 이 그걸
    재사용하면 설명만 바꾼 수정은 revision 을 못 움직이고, 낡은 목록을 든 전체 교체가 409 없이
    통과하며 그 수정을 조용히 되돌린다.
    """
    auth = _auth(client)
    client.put("/api/scan-presets/item/weekly", headers=auth,
               json=_preset("weekly", description="예전 설명"))
    stale = client.get("/api/scan-presets", headers=auth).json()
    stale_revision = stale["revision"]

    # 스캔 동작은 그대로 두고 설명만 바꾼다 → fingerprint 는 안 변한다.
    client.put("/api/scan-presets/item/weekly", headers=auth,
               json=_preset("weekly", description="새 설명"))
    after = client.get("/api/scan-presets", headers=auth).json()
    assert preset_store.fingerprint(after["presets"][0]) == preset_store.fingerprint(stale["presets"][0])
    assert after["revision"] != stale_revision

    r = client.put("/api/scan-presets", headers=auth,
                   json={"revision": stale_revision, "presets": stale["presets"]})
    assert r.status_code == 409, r.text
    assert client.get("/api/scan-presets", headers=auth).json()["presets"][0]["description"] == "새 설명"


def test_revision_tracks_every_persisted_field():
    """설명·이름 표기·저장 시각까지 — 저장되는 값이 달라지면 revision 도 달라져야 한다."""
    base = [_preset("weekly", description="a", updated_at="2026-01-01T00:00:00Z")]
    revision = preset_store.document_revision(preset_store.normalize_presets(base))
    for changed in (
        _preset("weekly", description="b", updated_at="2026-01-01T00:00:00Z"),
        _preset("Weekly", description="a", updated_at="2026-01-01T00:00:00Z"),
        _preset("weekly", description="a", updated_at="2026-02-02T00:00:00Z"),
        _preset("weekly", description="a", updated_at="2026-01-01T00:00:00Z", ports="8443"),
    ):
        assert preset_store.document_revision(preset_store.normalize_presets([changed])) != revision

    # 같은 내용이면 항목 순서가 달라도 같은 revision(정규화가 순서를 고정한다).
    pair = [_preset("b-name", updated_at="2026-01-01T00:00:00Z"),
            _preset("a-name", updated_at="2026-01-01T00:00:00Z")]
    assert preset_store.document_revision(preset_store.normalize_presets(pair)) \
        == preset_store.document_revision(preset_store.normalize_presets(list(reversed(pair))))


def test_two_stale_clients_cannot_both_replace_the_whole_list(client):
    """A·B 가 같은 목록을 읽고 각자 다른 목록을 PUT — 둘 다 200 이면 한쪽이 조용히 사라진다."""
    auth = _auth(client)
    shared = client.get("/api/scan-presets", headers=auth).json()["revision"]

    first = client.put("/api/scan-presets", headers=auth,
                       json={"revision": shared, "presets": [_preset("from-a")]})
    second = client.put("/api/scan-presets", headers=auth,
                        json={"revision": shared, "presets": [_preset("from-b")]})
    assert first.status_code == 200, first.text
    assert second.status_code == 409, second.text
    assert [p["name"] for p in client.get("/api/scan-presets", headers=auth).json()["presets"]] == ["from-a"]


def test_server_publishes_the_name_key_clients_must_not_recompute(client):
    """이름 정규화가 클라이언트마다 다르면 '교체'가 '중복 생성'이 된다 — 기준을 서버가 준다."""
    auth = _auth(client)
    client.put("/api/scan-presets/item/Weekly  Full", headers=auth, json=_preset("Weekly  Full"))
    listed = client.get("/api/scan-presets", headers=auth).json()["presets"]
    assert listed[0]["name"] == "Weekly Full"          # 연속 공백은 접어서 저장
    assert listed[0]["name_key"] == "weekly full"

    # 표기가 다른 같은 이름은 새 항목이 아니라 교체다(예전 프론트 규칙이라면 400 중복이 났다).
    r = client.put("/api/scan-presets/item/weekly full", headers=auth,
                   json=_preset("weekly full", ports="8443"))
    assert r.status_code == 200, r.text
    assert len(r.json()["presets"]) == 1
    assert r.json()["presets"][0]["ports"] == "8443"
    assert r.json()["name"] == "weekly full"


def test_create_only_upsert_refuses_to_overwrite_an_existing_name(client):
    """예전 localStorage 프리셋 이관이 서버의 동명 프리셋을 덮어쓰면 안 된다."""
    auth = _auth(client)
    client.put("/api/scan-presets/item/weekly", headers=auth, json=_preset("weekly", ports="22"))
    r = client.put("/api/scan-presets/item/weekly?create_only=true", headers=auth,
                   json=_preset("weekly", ports="443"))
    assert r.status_code == 409, r.text
    assert client.get("/api/scan-presets", headers=auth).json()["presets"][0]["ports"] == "22"


def test_item_endpoints_reject_a_mismatched_or_path_hostile_name(client):
    auth = _auth(client)
    clash = client.put("/api/scan-presets/item/weekly", headers=auth, json=_preset("monthly"))
    assert clash.status_code == 400, clash.text
    assert client.delete("/api/scan-presets/item/nope", headers=auth).status_code == 404


def test_preset_names_cannot_contain_path_separators():
    """이름은 /item/{name} 경로 조각으로도 쓰인다 — 구분자가 섞이면 대상이 모호해진다."""
    for bad in ("a/b", "a\\b"):
        with pytest.raises(ValueError):
            preset_store.normalize_preset(_preset(bad))


def test_sync_unions_both_sides_when_no_name_collides(client):
    auth = _auth(client)
    client.put("/api/scan-presets/item/server-only", headers=auth, json=_preset("server-only"))
    r = client.post("/api/scan-presets/sync", headers=auth, json={"presets": [_preset("scanner-only")]})
    body = r.json()
    assert body["status"] == "synced"
    assert body["added_to_server"] == ["scanner-only"]
    assert body["added_to_client"] == ["server-only"]
    assert [p["name"] for p in body["presets"]] == ["scanner-only", "server-only"]
    # 응답 목록이 곧 양쪽이 가져야 할 최종 상태 — 서버 파일도 같아야 한다.
    assert [p["name"] for p in client.get("/api/scan-presets", headers=auth).json()["presets"]] \
        == ["scanner-only", "server-only"]


def test_sync_conflict_changes_nothing_on_the_server(client):
    auth = _auth(client)
    client.put("/api/scan-presets/item/weekly", headers=auth, json=_preset("weekly", ports="22"))
    r = client.post("/api/scan-presets/sync", headers=auth,
                    json={"presets": [_preset("weekly", ports="443"), _preset("brand-new")]})
    body = r.json()
    assert body["status"] == "conflict"
    assert [c["name"] for c in body["conflicts"]] == ["weekly"]
    # 충돌이면 부분 병합도 없다 — brand-new 가 몰래 들어가 있으면 안 된다.
    after = client.get("/api/scan-presets", headers=auth).json()["presets"]
    assert [p["name"] for p in after] == ["weekly"]
    assert after[0]["ports"] == "22"


def test_sync_rejects_a_preset_that_would_widen_the_option_whitelist(client):
    auth = _auth(client)
    bad = _preset("evil", options=["syn", "--script=http-shellshock"])
    assert client.post("/api/scan-presets/sync", headers=auth, json={"presets": [bad]}).status_code == 400
    assert not get_settings().preset_file.exists()


# ── 단독 스캐너와의 동일성 ──

def test_standalone_scanner_option_table_matches_the_web_registry():
    """옵션 키 → nmap 플래그 표는 두 곳에 복제되어 있다. 어긋나면 같은 프리셋이 다른 스캔이 된다."""
    scanner = _load_scanner()
    web = {o["key"]: list(o["flags"]) for o in scan_options.SCAN_OPTIONS}
    assert scanner.OPTION_FLAGS == web
    assert list(scanner.OPTION_FLAGS) == [o["key"] for o in scan_options.SCAN_OPTIONS]


def test_standalone_scanner_nse_table_matches_the_web_registry():
    scanner = _load_scanner()
    assert scanner.NSE_PROTO == {s["key"]: s.get("proto", "both") for s in scan_options.NSE_SCRIPTS}
    assert scanner.DEFAULT_PRESET_NSE == scan_options.NSE_DEFAULT_KEYS
    assert scanner.DEFAULT_AUTO_PRESET_OPTIONS == scan_options.DEFAULT_KEYS


def test_a_preset_written_by_the_scanner_loads_on_the_server_and_back(tmp_path):
    """같은 파일이 양쪽에 존재한다 — 형식이 정말 하나인지 왕복으로 확인한다."""
    scanner = _load_scanner()
    scanner_file = tmp_path / "scanops_presets.json"
    scanner.save_presets(scanner_file, [
        {"name": "주간 전수", "workflow": "auto", "options": scanner.DEFAULT_AUTO_PRESET_OPTIONS,
         "ports": "", "nse": scanner.DEFAULT_PRESET_NSE},
    ])
    from_server = preset_store.load(scanner_file)
    assert [p["name"] for p in from_server] == ["주간 전수"]

    server_file = tmp_path / "scan_presets.json"
    preset_store.save(server_file, from_server)
    round_tripped = scanner.load_presets(server_file)
    assert round_tripped == scanner.load_presets(scanner_file)
    # 지문까지 같아야 '내용이 같다'는 판정이 양쪽에서 일치한다.
    assert scanner.preset_fingerprint(round_tripped[0]) == preset_store.fingerprint(from_server[0])


# ── 도킹: 스캔 결과 업로드 ──

def test_known_results_lets_the_scanner_skip_what_the_server_already_has(client):
    """도킹할 때마다 폴더 전체를 올리면 같은 결과로 스캔 이력이 불어나고 닫힘 판정이 다시 돈다."""
    auth = _auth(client)
    xml = (Path(__file__).parent / "fixtures" / "sample_scan.xml").read_bytes()

    r = client.post("/api/scans/import", headers=auth,
                    files={"file": ("weekly.xml", xml, "text/xml")})
    assert r.status_code == 200, r.text

    from scanops.api.scans import result_fingerprint
    fingerprint = result_fingerprint([xml])
    known = client.post("/api/scans/known-results", headers=auth,
                        json={"fingerprints": [fingerprint, "0" * 64]}).json()
    assert known["known"] == [fingerprint]


def test_result_fingerprint_ignores_file_name_and_stage_order():
    """폴더를 복사해 다른 경로·다른 순서로 도킹해도 같은 결과로 인식돼야 중복이 막힌다."""
    from scanops.api.scans import result_fingerprint
    a, b = b"<nmaprun/>", b"<nmaprun x=''/>"
    assert result_fingerprint([a, b]) == result_fingerprint([b, a])
    assert result_fingerprint([a]) != result_fingerprint([b])


def test_scanner_and_server_compute_the_same_result_fingerprint():
    """지문 규칙이 두 곳에 복제돼 있다 — 어긋나면 중복 제거가 통째로 무력해진다."""
    from scanops.api.scans import result_fingerprint as server_side
    scanner = _load_scanner()
    payloads = [b"<nmaprun a=''/>", b"<nmaprun b=''/>"]
    assert scanner.result_fingerprint(payloads) == server_side(payloads)


def test_docking_collects_manifest_units_and_interrupted_xml_separately(tmp_path):
    """중단본은 manifest 가 없다 — 계약 없이 올라가 서버가 관측 전용으로 받는다."""
    scanner = _load_scanner()
    out = tmp_path / "scanops_scans"
    (out / scanner.INTERRUPTED_DIR_NAME).mkdir(parents=True)
    (out / "weekly.10.0.0.1.tcp_discovery.xml").write_bytes(b"<nmaprun/>")
    (out / "weekly.manifest.json").write_text(json.dumps({
        "tool": "scanops_scanner", "status": "done",
        "import_xml_files": [str(out / "weekly.10.0.0.1.tcp_discovery.xml")],
    }), encoding="utf-8")
    (out / scanner.INTERRUPTED_DIR_NAME / "adhoc.tcp_discovery.xml").write_bytes(b"<nmaprun p=''/>")

    units = scanner.collect_result_units(out)
    kinds = {u["kind"]: u for u in units}
    assert set(kinds) == {"manifest", "interrupted"}
    assert kinds["manifest"]["manifest"] is not None
    assert kinds["interrupted"]["manifest"] is None      # 계약 없음 = 닫힘 권한 없음
    assert kinds["interrupted"]["status"] == "interrupted"
    assert len({u["fingerprint"] for u in units}) == 2


def test_docking_uploads_only_units_the_server_does_not_have(tmp_path, monkeypatch, capsys):
    scanner = _load_scanner()
    out = tmp_path / "scanops_scans"
    out.mkdir(parents=True)
    (out / "a.xml").write_bytes(b"<nmaprun a=''/>")
    (out / "a.manifest.json").write_text(json.dumps({
        "tool": "scanops_scanner", "status": "done", "import_xml_files": [str(out / "a.xml")],
    }), encoding="utf-8")
    (out / "b.xml").write_bytes(b"<nmaprun b=''/>")
    (out / "b.manifest.json").write_text(json.dumps({
        "tool": "scanops_scanner", "status": "done", "import_xml_files": [str(out / "b.xml")],
    }), encoding="utf-8")

    already = scanner.result_fingerprint([b"<nmaprun a=''/>"])
    uploaded: list = []
    monkeypatch.setattr(scanner, "_sync_request",
                        lambda url, token, payload, timeout: {"known": [already]})
    monkeypatch.setattr(scanner, "_upload_unit",
                        lambda base, token, unit, timeout: uploaded.append(unit["name"]) or
                        {"counts": {"new": 1, "updated": 0}, "closure_mode": "manifest"})

    assert scanner.sync_results("http://server:8770", "t", out, 5.0) == 0
    assert uploaded == ["b"]                       # 이미 있는 a 는 다시 올리지 않는다
    assert "이미 가져온 것 1건" in capsys.readouterr().out


def test_resend_results_ignores_the_server_side_dedup(tmp_path, monkeypatch):
    scanner = _load_scanner()
    out = tmp_path / "scanops_scans"
    out.mkdir(parents=True)
    (out / "a.xml").write_bytes(b"<nmaprun a=''/>")
    (out / "a.manifest.json").write_text(json.dumps({
        "tool": "scanops_scanner", "status": "done", "import_xml_files": [str(out / "a.xml")],
    }), encoding="utf-8")

    uploaded: list = []
    def refuse(*_a, **_k):
        raise AssertionError("--resend-results 는 서버에 중복 확인을 묻지 않는다")
    monkeypatch.setattr(scanner, "_sync_request", refuse)
    monkeypatch.setattr(scanner, "_upload_unit",
                        lambda base, token, unit, timeout: uploaded.append(unit["name"]) or
                        {"counts": {"new": 0, "updated": 1}, "closure_mode": "manifest"})
    assert scanner.sync_results("http://s:8770", "t", out, 5.0, resend=True) == 0
    assert uploaded == ["a"]
