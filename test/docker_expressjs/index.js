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
  console.log("/api/get/ -> " + JSON.stringify(req.body));
  res.send("hello http");
});
app.use('/api/post', (req, res) => {
  console.log("/api/post/ -> " + JSON.stringify(req.body));
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
  .listen(9191, function () {
    console.log('http with ssl listening on port 9191')
  })

//// http2 without tls

const http2_server = http2.createServer();

function init_http2_server(http2server) {
  http2server.on('error', (err) => console.error(err));



  http2server.on('stream', (stream, headers) => {
    let body = '';

    if (headers[":method"] == 'GET' && headers[":path"] == "/") {
      console.log('getting http2')
      stream.respond({
        'content-type': 'text/plain',
        ':status': 200
      });
      stream.end('hello http2');

    }


    if (headers[":method"] == 'GET' && headers[":path"] == "/push") {
      console.log('getting http2 for push')
      stream.respond({
        'content-type': 'text/plain',
        ':status': 200
      });
      stream.end('hello push1');

      stream.pushStream({ ":path": "/deneme2.jpg" }, (err, pushStream) => {
        if (err)
          console.log(err);
        pushStream.respond({
          'content-type': 'text/plain',
          ':status': 200
        });
        pushStream.end('hello push2')
      })
      stream.pushStream({ ":path": "/deneme3.jpg" }, (err, pushStream) => {
        if (err)
          console.log(err);
        pushStream.respond({
          'content-type': 'text/plain',
          ':status': 200
        });
        pushStream.end('hello push3')
      })




    }

    stream.on('data', (data) => {
      console.log("data from stream " + stream.id + ":" + data);

    })
    if (headers[":method"] == 'POST') {
      console.log('posting http2 ' + body)
      stream.respond({
        'content-type': 'text/plain',
        ':status': 200
      });

      stream.on('data', (data) => {

        body = data;
        let datax = 'hello http2 post:' + body;
        console.log(datax);
        stream.end(datax);
      })



    }


  });

}
init_http2_server(http2_server);
http2_server.listen(9292, function () {
  console.log("http2 without ssl listening on port 9292");
})


const http2_server_tls = http2.createSecureServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.cert')
});
init_http2_server(http2_server_tls);
http2_server_tls.listen(9393, function () {
  console.log("http2 with ssl listening on port 9393");
})







//# sourceMappingURL=index.js.map