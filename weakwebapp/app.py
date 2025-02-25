from flask import Flask
from flask import make_response

app = Flask(__name__)

@app.route('/')
def weak_web_app():
    return 'WeakWebApp provided by IntegSec to test PentestTools and other tools.'
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

@app.route('/sitemap.xml')
def sitemap():
    sitemap_xml = '''<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url>
            <loc>http://example.com/</loc>
            <lastmod>2023-10-01</lastmod>
            <changefreq>monthly</changefreq>
            <priority>1.0</priority>
        </url>
    </urlset>'''
    response = make_response(sitemap_xml)
    response.headers['Content-Type'] = 'application/xml'
    return response

@app.after_request
def disable_security_headers(response):
    response.headers.pop('X-Content-Type-Options', None)
    response.headers.pop('X-Frame-Options', None)
    response.headers.pop('X-XSS-Protection', None)
    response.headers.pop('Content-Security-Policy', None)
    return response

@app.after_request
def insecure_cors_policy(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0',port=80)