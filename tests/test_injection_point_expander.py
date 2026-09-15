"""Injection-point expander — seed header/cookie/path points (the xsscrapy surface)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend_api.models.base import BaseModel
from backend_api.models.endpoint import Endpoint
from backend_api.models.param import Param
from backend_api.services.injection_point_expander import InjectionPointExpander


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    BaseModel.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _ep(db, url="https://acme.test/search", tid=1):
    e = Endpoint(target_id=tid, method="GET", url_pattern=url)
    db.add(e)
    db.commit()
    return e


def test_seeds_header_and_cookie_points(db):
    ep = _ep(db)
    n = InjectionPointExpander.seed_for_endpoint(db, ep.id, include_path=False)
    params = db.query(Param).filter(Param.endpoint_id == ep.id).all()
    headers = {p.name for p in params if p.location == "header"}
    cookies = {p.name for p in params if p.location == "cookie"}
    assert {"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"} <= headers
    assert "xssboss_probe" in cookies
    assert n == len(params)


def test_is_idempotent(db):
    ep = _ep(db)
    first = InjectionPointExpander.seed_for_endpoint(db, ep.id, include_path=False)
    second = InjectionPointExpander.seed_for_endpoint(db, ep.id, include_path=False)
    assert first > 0 and second == 0   # nothing re-seeded


def test_does_not_duplicate_existing(db):
    ep = _ep(db)
    db.add(Param(endpoint_id=ep.id, name="User-Agent", location="header"))
    db.commit()
    InjectionPointExpander.seed_for_endpoint(db, ep.id, include_path=False)
    ua = db.query(Param).filter(Param.endpoint_id == ep.id, Param.name == "User-Agent",
                                Param.location == "header").all()
    assert len(ua) == 1   # not duplicated


def test_path_seeded_only_for_templated_urls(db):
    flat = _ep(db, url="https://acme.test/search")
    templated = _ep(db, url="https://acme.test/users/{id}/profile")
    InjectionPointExpander.seed_for_endpoint(db, flat.id)
    InjectionPointExpander.seed_for_endpoint(db, templated.id)
    flat_paths = db.query(Param).filter(Param.endpoint_id == flat.id, Param.location == "path").all()
    tmpl_paths = db.query(Param).filter(Param.endpoint_id == templated.id, Param.location == "path").all()
    assert flat_paths == []                          # no placeholder -> no path point
    assert {p.name for p in tmpl_paths} == {"id"}    # {id} -> path injection point


def test_missing_endpoint_is_noop(db):
    assert InjectionPointExpander.seed_for_endpoint(db, 9999) == 0
