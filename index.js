//In this project is installed the audit fix module for the checking of dependency
//vulnerability with consequent automatic installation of updates

const express = require('express');
const app = express();
const http = require('http').Server(app);
const htp = require('http');
const io = require('socket.io')(http, {
  serveClient: true,
 // below are engine.IO options
 pingInterval: 10000,
 pingTimeout: 5000,
 cookie: false
});

var {google} = require('googleapis');
let privatekey = require("./auth.json");
const {JWT} = require('google-oauth-jwt');
const dialogflow = require('dialogflow');
const uuid = require('uuid');

//Sicurezza Node
const helmet = require('helmet');
const rateLimit = require("express-rate-limit");

//Var per mongodb e passaggio parametri
var bodyParser = require('body-parser');
var urlencodedParser = bodyParser.urlencoded({extended:false});
var urlencoded = bodyParser.urlencoded({extended:false});
var MongoClient = require('mongodb').MongoClient;
var url = 'mongodb://localhost:27017/';

//Module JSON Web Token
const jwt = require('jsonwebtoken');
const KEY ="secret";

//Module per criptare
const bcrypt = require('bcryptjs');
const saltRounds = 10;

//Module HTTPS
const fs = require('fs');
const https = require('https');
var key = fs.readFileSync('chiave.pem');
var cert = fs.readFileSync('certificato.pem');
var options = {
  key: key,
  cert: cert
};

// configure a JWT auth client for authentication Google
let jwtClient = new google.auth.JWT (
    privatekey.client_email,
    null,
    privatekey.private_key,
    ['https://www.googleapis.com/auth/dialogflow']);
      //authenticate request
      jwtClient.authorize(function (err, tokens) {
        if (err) {
              console.log(err);
              return;
        } else {
              console.log("Successfully connected!");
          }
      });

//Account limiter for prevent DOS Attach
const createAccountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 3, // start blocking after 5 requests
  message:
    "Troppi account creati dallo stesso indirizzo IP, prova fra un'ora"
});


    //Helmet module for prevent XSS Attach
    app.use(helmet())

    const server = http.listen(8080,function(){
      console.log ("Server su porta 8080")
    })

// we will pass our 'app' to 'https' server
/*https.createServer({
    key: fs.readFileSync('./chiave.pem'),
    cert: fs.readFileSync('./certificato.pem'),
}, app)
.listen(3000, function(){
  console.log('Server su porta 3000');
});*/
           
            app.get('/', function(req, res) {
                  res.render('home.ejs');
            });



           app.get('/login', createAccountLimiter, function(req,res){
             res.render('iniziale.ejs')
           });

           app.get('/register', createAccountLimiter, function(req,res){
            res.render('register.ejs')
          });

          app.post('/registerToDB', urlencoded,function(req,res){
            MongoClient.connect(url, function(err, db) {
              var dbo = db.db('Chat');
              bcrypt.hash(req.body.pass, saltRounds, function(err,hash){
                var myObj = { Nome: req.body.name, Password: hash};
                dbo.collection('user').insertOne(myObj, function(err,res){
                     if(err) throw err;
                     console.log("User inserted")
                })
             });
             res.render('iniziale.ejs');
          });
        });

          // app.get('/inizio', createAccountLimiter, function(req,res){
            //console.log('Sono qui')
           app.post('/demo',urlencodedParser,function(req,res){
            MongoClient.connect(url, function(err, db) {
              var dbo = db.db('Chat');
              dbo.collection('user').findOne({ Nome: req.body.name}, function(err, user) {
                if(user == null){
                  res.end("Login invalid");
                }
            else {
            bcrypt.compare(req.body.pass, user.Password, function(err, result){
              if (user.Nome == req.body.name && result == true){
                const token = jwt.sign({
                  uname: user.Nome,
                  pass: user.Password
                }, KEY, {
                  expiresIn: "1h"
                })
               res.render('index.ejs')
               console.log(token)
             } else {
               res.send("Password Incorrect");
             }
            })
          }
          });
          });
          });
      //});
           
        io.sockets.on('connection',function(socket) {
            socket.on('username', function(username) {
                socket.username = username;
                socket.emit('is_online', '🔵 <i>' + socket.username + ' è online..</i>');
            });
        
            socket.on('disconnect', function(username) {
                socket.emit('is_online', '🔴 <i>' + socket.username + ' left the chat..</i>');
            })
        
            socket.on('chat_message', function(message) {
                socket.emit('chat_message', '<strong>' + socket.username + '</strong>: ' + message);
                  runSample('newagent-spgvri',message);     
            });
        
        
            //Call Dialogflow API
            async function runSample(projectId,message) {
                // A unique identifier for the given session
                const sessionId = uuid.v4();
              
                // Create a new session
                const sessionClient = new dialogflow.SessionsClient({
                    keyFilename:"C:/Users/Vincenzo/Desktop/ProgettiNode/node-group-chat/auth.json"
                });
                const sessionPath = sessionClient.sessionPath(projectId, sessionId);
              
                // The text query request.
                const request = {
                  session: sessionPath,
                  queryInput: {
                    text: {
                      // The query to send to the dialogflow agent
                      text: message,
                      languageCode: 'it',
                    },
                  },
                };
                // Send request and log result
                const responses = await sessionClient.detectIntent(request);
                console.log('Detected intent');
                const result = responses[0].queryResult;
                console.log(`  Query: ${result.queryText}`);
                socket.emit('chat_message', '<strong>' + "Server: " + '</strong>:' + result.fulfillmentText);
                console.log(`  Response: ${result.fulfillmentText}`);
                if (result.intent) {
                  console.log(`  Intent: ${result.intent.displayName}`);
                } else {
                  console.log(`  No intent matched.`);
                }
              }
        });
      