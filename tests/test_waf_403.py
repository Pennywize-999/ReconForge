from reconforge.core.models import Host, WebEndpoint, WAFAnalysis, Confidence
from reconforge.web.waf.analyzer import WAFAnalyzer

def test_waf_403_does_not_trigger_detection():
    analyzer = WAFAnalyzer()
    host = Host(ip="127.0.0.1", status="up")
    
    # Add 15 403s
    for i in range(15):
        ep = WebEndpoint(url=f"http://127.0.0.1/admin{i}", path=f"/admin{i}", status_codes=[403])
        host.web_endpoints.append(ep)

    waf = analyzer.analyze_host(host)

    assert waf is not None
    assert waf.detected is False
    assert waf.confidence == Confidence.LOW

def test_waf_429_triggers_detection():
    analyzer = WAFAnalyzer()
    host = Host(ip="127.0.0.1", status="up")

    ep = WebEndpoint(url="http://127.0.0.1/admin", path="/admin", status_codes=[429])
    host.web_endpoints.append(ep)
    
    waf = analyzer.analyze_host(host)
    
    assert waf is not None
    assert waf.detected
    assert waf.rate_limiting
