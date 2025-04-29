const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8080;
const BROWSER_DEMO_DIR = path.join(__dirname, 'browser-demo');

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
};

const server = http.createServer((req, res) => {
  console.log(`Request: ${req.method} ${req.url}`);
  
  // Default to index.html for root path
  let filePath = req.url === '/' 
    ? path.join(BROWSER_DEMO_DIR, 'index.html')
    : path.join(BROWSER_DEMO_DIR, req.url);
  
  const extname = path.extname(filePath);
  const contentType = MIME_TYPES[extname] || 'text/plain';
  
  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        console.error(`File not found: ${filePath}`);
        res.writeHead(404);
        res.end('File not found');
      } else {
        console.error(`Server error: ${err.code}`);
        res.writeHead(500);
        res.end(`Server Error: ${err.code}`);
      }
      return;
    }
    
    // Special handling for WASM files to ensure proper MIME type
    if (extname === '.wasm') {
      res.writeHead(200, {
        'Content-Type': 'application/wasm',
        'Content-Disposition': 'inline',
      });
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
    }
    
    res.end(content);
  });
});

server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
  console.log(`Serving files from ${BROWSER_DEMO_DIR}`);
});
