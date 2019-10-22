"use strict";
// Import express
let express = require('express');
// Import Body parser
let bodyParser = require('body-parser');
const https = require('https');
const fs = require('fs')
const http2 = require('http2');
// Initialize the app
let app = express();
// Configure bodyparser to handle post requests
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());
var port = process.env.PORT || 9090;
// Send message for default URL
app.get('/', (req, res) => res.send('Hello World with Express'));
// Use Api routes in the App
app.get('/api/get', (req, res) => {
    console.log("/api/get/ -> "+ JSON.stringify(req.body));
    res.send("hello http");
});
app.use('/api/post', (req, res) => {
    console.log("/api/post/ -> "+JSON.stringify(req.body));
    res.json(req.body);
});

// http without tls
app.listen(port, function () {
    console.log("http without ssl listening  on port " + port);
});

///http with tls

https.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert')
  }, app)
  .listen(3000, function () {
    console.log('http with ssl listening on port 3000')
  })

  //// http2 without tls

  const http2server = http2.createServer();

http2server.on('error', (err) => console.error(err));

http2server.listen(9191,function(){
    console.log("http2 without ssl listening on port 9191");
})

http2server.on('stream', (stream, headers) => {
  let body='';

  if(headers[":method"]=='GET'){
    console.log('getting http2')
    stream.respond({
      'content-type': 'text/plain',
      ':status': 200
    });
    stream.end('hello http2');

  }
  stream.on('data',(data)=>{
    console.log("data from stream:"+data);
    body=data;
  })
  if(headers[":method"]=='POST'){
    console.log('posting http2 '+body)
    stream.respond({
      'content-type': 'text/plain',
      ':status': 200
    });
    stream.end('hello http2 post:'+body);

  }


});




//# sourceMappingURL=index.js.map