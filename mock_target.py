from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Vulnerable Mock Target Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/search")
def search(q: str = ""):
    # Basic unescaped reflection in three separate contexts: HTML, Attribute, and Script Block.
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Mock Vulnerable Target</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <div class="container" style="padding: 20px; font-family: sans-serif;">
        <h2>Vulnerable Search Dashboard</h2>
        
        <!-- Context 1: Raw HTML reflection -->
        <div class="result-box" style="border: 1px solid #ccc; padding: 10px; margin: 10px 0;">
            <p><strong>HTML reflection:</strong> You searched for: {q}</p>
        </div>
        
        <!-- Context 2: Attribute reflection -->
        <div class="result-box" style="border: 1px solid #ccc; padding: 10px; margin: 10px 0;">
            <p><strong>Attribute reflection:</strong></p>
            <input type="text" id="search-input" value="{q}" style="width: 100%; padding: 5px;" />
        </div>
        
        <!-- Context 3: Script context reflection -->
        <script>
            // Store search term in local variable
            var searchTerm = "{q}";
            console.log("Reflected search term:", searchTerm);
        </script>
    </div>
</body>
</html>"""
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("mock_target:app", host="127.0.0.1", port=8081, log_level="info")
