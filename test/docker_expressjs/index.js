"use strict";
// Import express
let express = require('express');
// Import Body parser
let bodyParser = require('body-parser');
const https = require('https');
const fs = require('fs')
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
    res.send("get captured successfully");
});
app.use('/api/post', (req, res) => {
    console.log("/api/post/ -> "+JSON.stringify(req.body));
    res.json(req.body);
});
app.use('/api/box/conf', (req, res) => {
    console.log(req.body);
    res.json({});
});
app.use('/api/box/createroamingclient', (req, res) => {
    console.log(req.body);
    res.json({});
});
app.use('/api/box/getbox', (req, res) => {
    console.log(req.body);
    res.json({});
});
app.use('/api/box/metrics', (req, res) => {
    console.log(req.body);
    res.json({});
});
// Launch app to listen to specified port
app.listen(port, function () {
    console.log("Running  on port " + port);
});

https.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert')
  }, app)
  .listen(3000, function () {
    console.log('ssl listening on port 3000! Go to https://localhost:3000/')
  })
//# sourceMappingURL=index.js.map