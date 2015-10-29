from bottle import route, run, request, response


@route('/')
def index():
    return """<html>
  <head>
    <title>History test server.</title>
  </head>
  <body>
    <p>A simple server to provide a handful of routes for various history
    purposes.</p>
    <ul>
      <li><a href="/test_get">GET Test</a></li>
      <li><a href="/test_post">POST Test</a></li>
      <li><a href="/test_poste">POST (encoding) Test</a></li>
      <li><a href="/test_cookies">Cookie Test</a></li>
    </ul>
  </body>
</html>"""


@route('/test_get')
def test_get():
    tmpl = """<html>
  <head>
    <title>GET Test</title>
  </head>
  <body>
    <form method="GET" action="/test_get">
      <input type="text" name="test0">
      <input type="submit" value="Submit">
    </form>
  </body>
</html>"""

    if 'test0' not in request.params:
        return tmpl
    else:
        return request.params['test0']


@route('/test_post', method=["GET", "POST"])
def test_post():
    tmpl = """<html>
  <head>
    <title>POST Test</title>
  </head>
  <body>
    <form method="POST" action="/test_post">
      <input type="text" name="test0">
      <input type="submit" value="Submit">
    </form>
  </body>
</html>"""

    if 'test0' not in request.params:
        return tmpl
    else:
        return request.params['test0']


@route('/test_poste', method=["GET", "POST"])
def test_post():
    tmpl = """<html>
  <head>
    <title>POST (encoding) Test</title>
  </head>
  <body>
    <form method="POST" action="/test_poste" enctype="multipart/form-data">
      <input type="text" name="test0">
      <input type="text" name="test1">
      <input type="submit" value="Submit">
    </form>
  </body>
</html>"""

    if 'test0' not in request.params:
        return tmpl
    else:
        return request.params['test0']


@route('/test_cookies')
def test_cookie():
    tmpl = """<html>
  <head>
    <title>GET Test</title>
  </head>
  <body>
    <p>Cookie is {0}</p>
  </body>
</html>"""

    val = int(request.cookies.get('test_cookie', '0'))

    response.set_cookie("test_cookie", str(val + 1))

    return tmpl.format(val)


if __name__ == "__main__":
    run(host='0.0.0.0', port='8087')
