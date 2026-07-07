"""Unit tests for FrameworkHarvester (Next.js, Nuxt, Remix, SvelteKit, Angular)."""
import json
import pytest
from recon_engine.framework_harvester import FrameworkHarvester, DiscoveredRoute


def test_nextjs_rsc_and_server_action_extraction():
    """Test extracting RSC flight chunks and Server Action IDs from HTML."""
    sample_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="/_next/static/chunks/main-app.js"></script>
    </head>
    <body>
        <script>
        self.__next_f.push([1, "1:[\"$\",\"$L2\",null,{\"children\":[\"$\",\"div\",null,{\"data-action\":\"/api/v1/checkout/submit\"}]}]"]);
        self.__next_f.push([1, "2:{\"actionId\":\"a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\"}"]);
        </script>
    </body>
    </html>
    """
    harvester = FrameworkHarvester("https://target-app.com")
    routes = harvester.harvest_nextjs(sample_html)
    assert len(routes) >= 2

    # Verify discovered API route
    api_routes = [r for r in routes if "/api/v1/checkout/submit" in r.path]
    assert len(api_routes) > 0
    assert api_routes[0].framework == "nextjs_rsc"

    # Verify Server Action
    actions = [r for r in routes if r.source_type == "rsc_server_action"]
    assert len(actions) > 0
    assert actions[0].headers.get("Next-Action") == "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"


def test_remix_manifest_extraction():
    """Test parsing window.__remixManifest and data loaders."""
    sample_html = """
    <script>
    window.__remixManifest = {
        "routes": {
            "root": { "id": "root", "path": "" },
            "routes/admin.dashboard": { "id": "routes/admin.dashboard", "path": "admin/dashboard" },
            "routes/users.$userId": { "id": "routes/users.$userId", "path": "users/:userId" }
        }
    };
    </script>
    """
    harvester = FrameworkHarvester("https://remix-app.com")
    routes = harvester.harvest_remix(sample_html)
    assert len(routes) >= 4

    # Check loader endpoints
    loader_routes = [r for r in routes if r.source_type == "remix_loader"]
    assert len(loader_routes) >= 2
    assert any("admin/dashboard" in r.path for r in loader_routes)
    assert any("users/:userId" in r.path for r in loader_routes)


def test_nuxt_and_angular_extraction():
    """Test Nuxt inline state and Angular TransferState parsing."""
    sample_html = """
    <script>window.__NUXT__={data:[{path:"/user/profile",auth:true}]};</script>
    <script id="serverApp-state" type="application/json">{"/api/v2/user/settings":{"theme":"dark"}}</script>
    """
    harvester = FrameworkHarvester("https://spa-app.com")
    routes = harvester.harvest_all(sample_html)
    
    nuxt_routes = [r for r in routes if r.framework == "nuxt_state"]
    assert len(nuxt_routes) > 0
    assert any("/user/profile" in r.path for r in nuxt_routes)

    angular_routes = [r for r in routes if r.framework == "angular"]
    assert len(angular_routes) > 0
    assert any("/api/v2/user/settings" in r.path for r in angular_routes)
