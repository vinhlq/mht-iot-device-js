var crypto=require('crypto');
var ca = require('../lib/ca.js');
var forge = require('node-forge')
var pki = forge.pki;
var AWS = require('aws-sdk');
var iot = new AWS.Iot();
// AWS SDK was loaded after bluebird, set promise dependency
AWS.config.setPromisesDependency(Promise);


function topicValidate(args){
    if(args.publishTopic === undefined) args.publishTopic = [];
    if(args.receiveTopic === undefined) args.receiveTopic = [];
    if(args.subscribeTopic === undefined) args.subscribeTopic = [];
    if(args.updateThingShadow === undefined) args.updateThingShadow = [];
    if(args.getThingShadow === undefined) args.getThingShadow = [];
    if(args.deleteThingShadow === undefined) args.deleteThingShadow = [];
}

function createPolicyDocument (args) {
    var args = arguments.length > 0 ? arguments[0]:{};

    topicValidate(args.allow);
    topicValidate(args.deny);

    policyDocument = {
        Version: "2012-10-17",
        Statement: [
            {
                Effect: "Allow",
                Action: ["iot:Connect"],
                Resource: [
                    util.format("arn:aws:iot:%s:%d:client/%s", process.env.AWS_REGION, args.accountNumber, args.clientId)
                ]
            },
            {
                Effect: "Allow",
                Action: ["iot:Subscribe"],
                Resource: [
                    util.format("arn:aws:iot:%s:%d:topicfilter/%s", process.env.AWS_REGION, args.accountNumber, args.clientId)
                ]
            },
            {
                Effect: "Allow",
                Action: [
                    "iot:Publish",
                    "iot:Receive"
                ],
                Resource: [
                    util.format("arn:aws:iot:%s:%d:topic/%s", process.env.AWS_REGION, args.accountNumber, args.clientId)
                ]
            }
        ]
    }

    for(i = 0; i < args.allow.publishTopic.length; i++){
        // TODO
    };
    args.allow.publishTopic.push(args.clientId);
    

    for(i = 0; i < args.allow.receiveTopic.length; i++){
        // TODO
    };
    args.allow.receiveTopic.push(args.clientId);
    
    for(i = 0; i < args.allow.subscribeTopic.length; i++){
        // TODO
    };
    args.allow.subscribeTopic.push(args.clientId);
    
    return {topic: {allow: args.allow, deny: args.deny}, document: policyDocument};
}

function defaultClientId(){
    return crypto.randomBytes(Math.ceil(12/2)).toString('hex').slice(0,12).toUpperCase();
}

function defaultThingName(clientId){
    return "mht-" + clientId;
}

class Iot {
    constructor(){
        this.iot = new AWS.Iot()
    }
    generateCA(args, registrationCode, callback){
        args = args || {};
        
        args.cert = args.cert || {};
        args.csr = args.csr || {};

        return new Promise((resolve, reject) => {
            args.cert.attrs = args.cert.attrs || {};
            var attrs = [{
                name: 'countryName',
                value: args.cert.attrs.countryName || 'VN'
            }, {
                shortName: 'ST',
                value: args.cert.attrs.ST || 'Hanoi'
            }, {
                name: 'localityName',
                value: args.cert.attrs.localityName || 'Hanoi'
            }, {
                name: 'organizationName',
                value: args.cert.attrs.organizationName || 'minhhatech'
            }, {
                shortName: 'OU',
                value: args.cert.attrs.OU || 'MHT'
            }, {
                name: 'commonName',
                value: registrationCode
            }];
            
            var params = {
                attrs: attrs
            };
            ca.createCACertificate(params, (err, result) => {
                if(err){
                    return callback ? callback(err) : reject(err);
                }
                return resolve(result);
            });
        })
        .then(function (result) {
            return new Promise((resolve, reject) => {

                args.csr.attrs = args.csr.attrs || {};
                var attrs = [{
                    name: 'countryName',
                    value: args.csr.attrs.countryName || 'VN'
                }, {
                    shortName: 'ST',
                    value: args.csr.attrs.ST || 'Hanoi'
                }, {
                    name: 'localityName',
                    value: args.csr.attrs.localityName || 'Hanoi'
                }, {
                    name: 'organizationName',
                    value: args.csr.attrs.organizationName || 'minhhatech'
                }, {
                    shortName: 'OU',
                    value: args.csr.attrs.OU || 'MHT'
                }, {
                    name: 'commonName',
                    value: registrationCode
                }];
                
                var params = {
                    attrs: attrs
                };
                ca.createVerificationCertificateFromCA(params, result.caCert, result.caKey, (err, cert) => {

                    if (err){
                        return callback ? callback(err) : reject(err);
                    }
                    
                    // var pem = pki.certificateToPem(cert);
                    // console.log(pem);

                    var data = {    cert: cert,
                                    caCert: result.caCert,
                                    caKey: result.caKey
                            };
                    return callback ? callback(null, data) : resolve(data);
                });
            });
        })
    }

    registerCA(cert, caCert, callback){
        return new Promise((resolve, reject) => {
            
            var caCertPem = pki.certificateToPem(caCert);
            var certPem = pki.certificateToPem(cert);

            var params = {
                caCertificate: caCertPem, /* required */
                verificationCertificate: certPem, /* required */
                allowAutoRegistration: true,
                setAsActive: true
            };
            this.iot.registerCACertificate(params, (err, data) => {
                if (err){
                    return callback ? callback(err) : reject(err);
                }
                return callback ? callback(null, data) : resolve(data);
                
                //console.log(data);           // successful response
            });
        });
    }

    generateAndRegisterCA(args, callback){
        return new Promise((resolve, reject) => {
            return new Promise((resolve, reject) => {
                this.iot.getRegistrationCode({}, function (err, data) {
                    
                    if (err){
                        return callback ? callback(err) : reject(err);
                    }
                    
                    resolve(data.registrationCode);
                });
            })
            .then((registrationCode) => {
                return this.generateCA(args, registrationCode);
            })
            .then((result) => {
                return this.registerCA(result.cert, result.caCert, (err, data) => {
                    if (err){
                        return callback ? callback(err) : reject(err);
                    }
                    result.response = data;
                    return callback ? callback(null, result) : resolve(result);
                });
            })
        });
    }








    describeEndpoint(){
        return this.iot.describeEndpoint(arguments).promise();
    }

    async createPrincipal(){
        // getCallerIdentity
        var sts = new AWS.STS();
        var identity = await sts.getCallerIdentity().promise()

        var args = arguments.length > 0 ? arguments[0]:{};
        var clientId = args.clientId !== undefined ? args.clientId:defaultClientId();

        var policyData={};
        if(args.policyDocument !== undefined){
            policyData.document = args.policyDocument;
        }
        else{
            var thingName = args.thingName !== undefined ? args.thingName:defaultThingName();
            var allow = args.allow !== undefined ? args.allow:{}
            var deny = args.deny !== undefined ? args.deny:{}
            var params={
                accountNumber: identity.Account,
                thingName: thingName,
                clientId: clientId,
                allow: allow,
                deny: deny
            }
            policyData = createPolicyDocument(params)
        }

        // createPolicy
        var params = {
            policyDocument: JSON.stringify(policyData.document), /* required */
            policyName: util.format("policy-%s", args.clientId)
        };
        console.log(params.policyDocument)
        var policy = this.iot.createPolicy(params).promise()

        // createKeysAndCertificate
        var params = {
            setAsActive: true
        };
        var cert = this.iot.createKeysAndCertificate(params).promise()

        // wait for policy & cert
        const result = await Promise.all([policy, cert])

        // attachPolicy
        var params = {
            policyName: result[0].policyName,
            target: result[1].certificateArn
        };
        await this.iot.attachPolicy(params).promise()

        return new Promise(function (resolve, reject) {
            resolve({policy: result[0], policyData: policyData, cert: result[1]});
        })
    }

    async createThing(){
        var args = arguments.length > 0 ? arguments[0]:{};
        var serialNumber = args.serialNumber !== undefined ? args.serialNumber:"SN-"+crypto.randomBytes(Math.ceil(12/2)).toString('hex').slice(0,15).toUpperCase();
        var clientId = args.clientId !== undefined ? args.clientId:crypto.randomBytes(Math.ceil(12/2)).toString('hex').slice(0,12).toUpperCase();
        var thingName = args.thingName !== undefined ? args.thingName:"mht-" + clientId;
        var allow = args.allow !== undefined ? args.allow:{}
        var deny = args.deny !== undefined ? args.deny:{}

        var params = {
            thingName: thingName,
            clientId: clientId,
            allow: allow,
            deny: deny
        };
        var principal = this.createPrincipal(params)

        // createThing
        var params = {
            thingName: thingName,
            attributePayload: {
                attributes: {
                    'clientId': clientId,
                },
            },
            // merge: true
        };
        var thing = this.iot.createThing(params).promise()

        // wait for thing & principal
        const result = await Promise.all([principal, thing])

        // attachThingPrincipal
        var params = {
            principal: result[0].cert.certificateArn,
            thingName: result[1].thingName
        };
        await this.iot.attachThingPrincipal(params).promise()

        return new Promise(function (resolve, reject) {
            resolve({clientId:clientId, principal: result[0], thing: result[1]});
        })
    }
}

module.exports = Iot;;