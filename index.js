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


//Module for file .env
const dotenv = require('dotenv');
dotenv.config();

//Var per mongodb e passaggio parametri
var bodyParser = require('body-parser');
var urlencodedParser = bodyParser.urlencoded({extended:false});
var urlencoded = bodyParser.urlencoded({extended:false});
var MongoClient = require('mongodb').MongoClient;
//var url = 'mongodb://'+process.env.DB_MONGO+':'+process.env.DB_MONGOPORT+'/';
var url = process.env.NOSQL_URL;

//Module JSON Web Token
const jwt = require('jsonwebtoken');
const KEY ="secret";

//Module per criptare
const bcrypt = require('bcryptjs');
const crypt = require('crypt');
const saltRounds = 10;

/*
//Module HTTPS
var fs = require('fs');
var https = require('https');
var key = fs.readFileSync('chiave.pem');
var cert = fs.readFileSync('certificato.pem');
var options = {
  key: key,
  cert: cert
};
*/
/*
const {Client} = require('pg');
var connectionString = 'postgres://enzoLiguo:vincenzo@localhost:5432/Users';
var clientDB = new Client({
  connectionString:connectionString
});
clientDB.connect();
*/



//Connecting to PostgreSQL Database
const {Client} = require('pg');
//var connectionString = 'postgres://'+ process.env.DB_USER +':'+process.env.DB_PASSWORD+'@'+process.env.DB_HOST+':'+process.env.DB_PORT+'/'+process.env.DB_DATABASE+'';
//var connectionString = ;
var clientDB = new Client({
  connectionString: process.env.DATABASE_URL
});
clientDB.connect();






const querystring = require('querystring');
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
    "Too many accounts created from the same IP address, please try the time"
});


    //Helmet module for prevent XSS Attach
    app.use(helmet())
    var port = process.env.PORT || 8080;

    const server = http.listen(port,function(){
      console.log ("Server listening on port " + port);
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
             res.render('iniziale.ejs');
           });

           app.get('/register', createAccountLimiter, function(req,res){
            res.render('register.ejs');
          });
          

          app.post('/registerToDB',urlencoded, function(req,res){
            bcrypt.hash(req.body.pass, saltRounds, function(err,hash){
              var myObj = new Array();
              myObj = [req.body.name,  hash];
              console.log(myObj);
              const text='INSERT INTO utenti VALUES($1,$2)';
              try{
                
                    clientDB.query(text, myObj, function(err,ress){
                    if (err) {
                      console.log(err.stack);
                    }
                    else console.log("result " + ress); 
                  });  
              }catch ( e){
                console.log(e);
              }
            });
          })
          
          /*app.post('/registerToDB', urlencoded,function(req,res){
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
        */

         app.post('/demo', urlencodedParser, function(req,res){

            var sql = 'SELECT utenti.password FROM utenti WHERE username = $1';
            var values = [req.body.name];
            
            clientDB.query(sql,values, function(err,ress){
              var psw = ress.rows[0].password;
              console.log(ress.rows[0].password);

              bcrypt.compare(req.body.pass, psw, function(err, result){
                if(result == true) {
                  var token = jwt.sign({
                    uname: req.body.name,
                    pass: req.body.pass
                  }, KEY, {
                    expiresIn: "1h"
                  });
                 res.render('index.ejs');
                 console.log(token);
               } else {
                 res.render('iniziale.ejs');
               }
                });
            });
          });
          


            

          /*app.post('/demo',urlencodedParser,function(req,res){
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
               res.render('iniziale.ejs')
             }
            })
          }
          });
          });
          });
      */
          
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
                user = socket.username;
                  runSample('newagent-spgvri',message,user);     
            });
        
        
            //Call Dialogflow API
            async function runSample(projectId,message,user) {
                // A unique identifier for the given session
                const sessionId = uuid.v4();
                const idUser = Math.round(100*Math.random());
              
                // Create a new session
                const sessionClient = new dialogflow.SessionsClient({
                    keyFilename:"./auth.json"
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


                //To save the chat in the database
                MongoClient.connect(url, function(err, db) {
                  var dbo = db.db(process.env.DB_SQL);
                    var myObj = {Username: user, Id_conversation: sessionId, User_message: result.queryText, Server_response:result.fulfillmentText, Intent: result.intent.displayName};
                    dbo.collection(process.env.DB_COLLECTION).insertOne(myObj, function(err,res){
                         if(err) throw err;
                         console.log("Chat inserted")
                    })
                
              });

              }
              

              
              

        });
      