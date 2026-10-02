from app.services.url_analyzer import analyze_url

def test_ip_url_is_flagged():
    result = analyze_url("http://192.0.2.10/login")
    assert result["score"] > 0
    assert any("IP address" in x for x in result["findings"])

def test_normal_https_url():
    result = analyze_url("https://example.com/")
    assert result["verdict"] == "Low Risk"
