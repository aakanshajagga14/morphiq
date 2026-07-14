import asyncio
import logging
from datetime import datetime
from aiohttp import web

LOG_FILE = "demo_access.log"

# Beautiful HTML for the login page
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Snoop Demo - Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { 
            background: radial-gradient(circle at center, #0a0e1a, #05070a); 
            height: 100vh; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            color: white; 
        }
        .login-card {
            background: rgba(255, 255, 255, 0.03);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            padding: 40px;
            border-radius: 20px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        h2 { text-align: center; margin-bottom: 30px; font-weight: 700; font-size: 24px; }
        .input-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-size: 14px; color: #a1a1aa; }
        input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            color: white;
            font-size: 16px;
            outline: none;
            transition: border-color 0.3s;
        }
        input:focus { border-color: #00d4ff; }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #00d4ff, #007bff);
            border: none;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            font-size: 16px;
            cursor: pointer;
            transition: opacity 0.3s, transform 0.1s;
        }
        button:hover { opacity: 0.9; }
        button:active { transform: scale(0.98); }
        .message { margin-top: 20px; text-align: center; font-size: 14px; color: #ff3366; min-height: 20px; }
        .sim-buttons { margin-top: 30px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 20px; }
        .sim-btn {
            background: rgba(255,51,102,0.1);
            border: 1px solid rgba(255,51,102,0.3);
            color: #ff3366;
            margin-bottom: 10px;
        }
        .sim-btn:hover { background: rgba(255,51,102,0.2); }
    </style>
</head>
<body>
    <div class="login-card">
        <h2>Secure Portal</h2>
        <form id="loginForm" method="POST" action="/login">
            <div class="input-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="admin">
            </div>
            <div class="input-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••">
            </div>
            <button type="submit">Sign In</button>
        </form>
        <div id="message" class="message"></div>

        <div class="sim-buttons">
            <label style="text-align: center; margin-bottom: 15px; color: white;">Try Hacking Me:</label>
            <button class="sim-btn" onclick="attack('sql')">Simulate SQL Injection</button>
            <button class="sim-btn" onclick="attack('path')">Simulate Path Traversal</button>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            try {
                const res = await fetch('/login', { method: 'POST', body: formData });
                document.getElementById('message').innerText = await res.text();
            } catch (err) {
                document.getElementById('message').innerText = "Network Error (Are you blocked?)";
            }
        });

        async function attack(type) {
            let path = "";
            if (type === 'sql') path = "/login?user=admin' OR 1=1--";
            if (type === 'path') path = "/images/../../../etc/passwd";
            
            try {
                const res = await fetch(path);
                document.getElementById('message').innerText = await res.text();
            } catch (err) {
                document.getElementById('message').innerText = "Network Error (Are you blocked?)";
            }
        }
    </script>
</body>
</html>
"""

def write_log(request: web.Request, status: int, bytes_sent: int = 0):
    """Writes a line to the access log in Nginx format."""
    now_str = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    # In a real environment, IP comes from request.remote. For local testing, we'll fake random malicious IPs if it's an attack
    ip = "127.0.0.1"
    
    path_and_query = request.path
    if request.query_string:
        path_and_query += f"?{request.query_string}"

    # If it's an attack, fake a remote IP so we can see it banned separately from localhost
    if "admin'" in path_and_query or "../" in path_and_query:
        ip = "198.51.100.42"

    log_line = f'{ip} - - [{now_str}] "{request.method} {path_and_query} HTTP/1.1" {status} {bytes_sent} "-" "{request.headers.get("User-Agent", "Mozilla/5.0")}"\n'
    
    with open(LOG_FILE, "a") as f:
        f.write(log_line)

async def handle_home(request: web.Request):
    write_log(request, 200, len(LOGIN_HTML))
    return web.Response(text=LOGIN_HTML, content_type='text/html')

async def handle_login(request: web.Request):
    data = await request.post()
    write_log(request, 401, 20)
    return web.Response(text="Invalid credentials.", status=401)

async def handle_attack(request: web.Request):
    write_log(request, 404, 0)
    return web.Response(text="Resource not found.", status=404)

app = web.Application()
app.router.add_get('/', handle_home)
app.router.add_post('/login', handle_login)
# Catch-all for attack simulations
app.router.add_get('/{tail:.*}', handle_attack)

if __name__ == '__main__':
    print(f"🚀 Starting Demo Login App on http://localhost:8080")
    print(f"📝 Writing logs to: {LOG_FILE}")
    web.run_app(app, port=8080)
