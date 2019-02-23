util=require('util');
crypto=require('crypto');
require('dotenv').config()

var AWS = require('aws-sdk');
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

class Iot{
    constructor(){
        this.iot = new AWS.Iot()
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

module.exports=Iot;