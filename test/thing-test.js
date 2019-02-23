require('dotenv').config()
util=require('util');
fs=require('fs')
Iot = require('../aws/iot.js')
var awsDevice = require('aws-iot-device-sdk');

iot = new Iot();

function writeFile(filename, data){
    return new Promise(function (resolve, reject) {
        fs.writeFile(filename, data, function(err){
            if(err) reject(err);
            else    resolve()
        })
    });
}

function deviceRun(args){
    var device = awsDevice.device({
        keyPath: args.privateKey,
       certPath: args.certificate,
         caPath: './aws-root-ca.pem',
       clientId: args.clientId,
           host: args.endpoint.endpointAddress,
           port: 8883
     });
     
     //
     // Device is an instance returned by mqtt.Client(), see mqtt.js for full
     // documentation.
     //
     device
       .on('connect', function() {
         console.log('connect');
         device.subscribe(args.clientId);
         setInterval(function() {
             console.log('publish');
             device.publish(args.clientId, JSON.stringify({ test_data: 1}));
         }, 1000);
       });
     device
         .on('close', function() {
             console.log('close');
         });
     device
         .on('reconnect', function() {
             console.log('reconnect');
         });
     device
         .on('offline', function() {
             console.log('offline');
         });
     device
         .on('error', function(error) {
             console.log('error', error);
         });
     device
         .on('publish', function(topic) {
             console.log('publish', topic);
         });
     device
         .on('message', function(topic, payload) {
             console.log('message', topic, payload.toString());
         });
}

try{
    iot.createThing()
    .then(function(result){
        console.log(JSON.stringify(result))

        var certificate = util.format("./certs/%s.certificate.pem.crt", result.thing.thingName);
        var f1=writeFile(certificate, result.principal.cert.certificatePem);

        var privateKey = util.format("./certs/%s.private.pem.key", result.thing.thingName);
        var f2=writeFile(privateKey, result.principal.cert.keyPair.PrivateKey);

        var publicKey = util.format("./certs/%s.public.pem.key", result.thing.thingName);
        var f3=writeFile(publicKey, result.principal.cert.keyPair.PublicKey);

        Promise.all([f1,f2,f3])
        .then(function()
        {
            return new Promise(function(resolve, reject){
                iot.describeEndpoint()
                .then(function(data){
                    resolve(data);
                })
            })
        })
        .then(function(data){
            var params={
                endpoint: data,
                clientId: result.clientId,
                certificate: certificate,
                privateKey: privateKey,
                publicKey: publicKey
            };
            deviceRun(params);
        });
    });
}catch(err){
    console.error(err)
}