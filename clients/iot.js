'use strict';
const crypto = require('crypto');
const ca = require('../lib/ca.js');
const forge = require('node-forge')
const pki = forge.pki;
const AWS = require('aws-sdk');
// AWS SDK was loaded after bluebird, set promise dependency
AWS.config.setPromisesDependency(Promise);


function topicValidate(args) {
  if (args.publishTopic === undefined) args.publishTopic = [];
  if (args.receiveTopic === undefined) args.receiveTopic = [];
  if (args.subscribeTopic === undefined) args.subscribeTopic = [];
  if (args.updateThingShadow === undefined) args.updateThingShadow = [];
  if (args.getThingShadow === undefined) args.getThingShadow = [];
  if (args.deleteThingShadow === undefined) args.deleteThingShadow = [];
}

function createPolicyDocument(args) {
  var args = args || {};

  topicValidate(args.allow);
  topicValidate(args.deny);

  const policyDocument = {
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

  for (let i = 0; i < args.allow.publishTopic.length; i++) {
    // TODO
  };
  args.allow.publishTopic.push(args.clientId);


  for (let i = 0; i < args.allow.receiveTopic.length; i++) {
    // TODO
  };
  args.allow.receiveTopic.push(args.clientId);

  for (let i = 0; i < args.allow.subscribeTopic.length; i++) {
    // TODO
  };
  args.allow.subscribeTopic.push(args.clientId);

  return { topic: { allow: args.allow, deny: args.deny }, document: policyDocument };
}

function defaultClientId() {
  return crypto.randomBytes(Math.ceil(12 / 2)).toString('hex').slice(0, 12).toUpperCase();
}

function defaultThingName(clientId) {
  return "mht-" + clientId;
}

class Iot {
  constructor() {
    this.awsIot = new AWS.Iot()
  }

  parseArn(arn) {
    // http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
    const elements = arn.split(':', 6)
    if (elements && elements.length > 5) {
      const result = {
        'arn': elements[0],
        'partition': elements[1],
        'service': elements[2],
        'region': elements[3],
        'account': elements[4],
        'resource': elements[5],
        'resource_type': null,
        'qualifier': null
      }
      if (result['resource'].includes('/')) {
        const resource = result['resource'].split('/', 3)
        result['resource_type'] = resource[0];
        result['resource'] = resource[1];
        result['qualifier'] = resource[2] || null;
      }
      else if (result['resource'].includes(':')) {
        const resource = result['resource'].split(':', 3);
        result['resource_type'] = resource[0];
        result['resource'] = resource[1];
        result['qualifier'] = resource[2] || null;
      }
      return result
    }
    else {
      return null;
    }
  }

  describeEndpoint() {
    return this.awsIot.describeEndpoint(arguments).promise();
  }

  createDeviceCertificate(args, commonName, serialNumber, caCert, caKey, callback) {
    var args = args || {};

    return new Promise((resolve, reject) => {
      args.attrs = args.attrs || {};
      const attrs = [{
        name: 'countryName',
        value: args.attrs.countryName || 'VN'
      }, {
        shortName: 'ST',
        value: args.attrs.ST || 'Hanoi'
      }, {
        name: 'localityName',
        value: args.attrs.localityName || 'Hanoi'
      }, {
        name: 'organizationName',
        value: args.attrs.organizationName || 'minhhatech'
      }, {
        shortName: 'OU',
        value: args.attrs.OU || 'MHT'
      }, {
        name: 'commonName',
        value: commonName
      }];

      var params = {
        serialNumber: serialNumber,
        attrs: attrs
      };
      ca.createVerificationCertificateFromCA(params, caCert, caKey, (err, data) => {
        if (err) {
          return callback ? callback(err) : reject(err);
        }

        const data1 =
        {
          cert: data.cert,
          keys: data.keys
        };
        return callback ? callback(null, data1) : resolve(data1);
      });
    });
  }

  generateCA(args, registrationCode, callback) {
    args = args || {};

    args.cert = args.cert || {};
    args.csr = args.csr || {};

    return new Promise((resolve, reject) => {
      args.cert.attrs = args.cert.attrs || {};
      const attrs = [{
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
        if (err) {
          return callback ? callback(err) : reject(err);
        }

        args.csr.attrs = args.csr.attrs || {};
        const attrs = [{
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
        ca.createVerificationCertificateFromCA(params, result.caCert, result.caKey, (err, data) => {

          if (err) {
            return callback ? callback(err) : reject(err);
          }

          // const pem = pki.certificateToPem(cert);
          // console.log(pem);

          const data1 =
          {
            cert: data.cert,
            caCert: result.caCert,
            caKey: result.caKey
          };
          return callback ? callback(null, data1) : resolve(data1);
        });
      });
    })
  }

  registerCA(args, callback) {
    return new Promise((resolve, reject) => {

      if (!args || !args.caCert || !args.cert) {
        const err = new Error('Parameter error');
        return callback ? callback(err) : reject(err);
      }
      const caCertPem = pki.certificateToPem(args.caCert);
      const certPem = pki.certificateToPem(args.cert);

      var params = {
        caCertificate: caCertPem, /* required */
        verificationCertificate: certPem, /* required */
        allowAutoRegistration: args.allowAutoRegistration === false ? false : true,
        setAsActive: args.setAsActive === false ? false : true
      };
      this.awsIot.registerCACertificate(params, (err, data) => {
        if (err) {
          return callback ? callback(err) : reject(err);
        }
        return callback ? callback(null, data) : resolve(data);

        //console.log(data);           // successful response
      });
    });
  }

  generateAndRegisterCA(args, callback) {
    return new Promise((resolve, reject) => {
      this.awsIot.getRegistrationCode().promise()
        .then((data) => {
          return this.generateCA(args, data.registrationCode);
        })
        .then((result) => {
          var params = {
            cert: result.cert,
            caCert: result.caCert,
            allowAutoRegistration: args.allowAutoRegistration,
            setAsActive: args.setAsActive
          };
          return this.registerCA(params, (err, data) => {
            if (err) {
              return callback ? callback(err) : reject(err);
            }
            result.response = data;
            return callback ? callback(null, result) : resolve(result);
          });
        })
        .catch((err) => {
          return callback ? callback(err) : reject(err);
        })
    });
  }






  createPolicy(args, callback) {
    args = args || {};

    return new Promise((resolve, reject) => {
      // getCallerIdentity
      const sts = new AWS.STS();
      return sts.getCallerIdentity({}, (err, identity) => {
        if (err) {
          return callback ? callback(err) : reject(err);
        }

        const clientId = args.clientId !== undefined ? args.clientId : defaultClientId();

        const policyData = {};
        if (args.policyDocument !== undefined) {
          policyData.document = args.policyDocument;
        }
        else {
          const thingName = args.thingName !== undefined ? args.thingName : defaultThingName();
          const allow = args.allow !== undefined ? args.allow : {}
          const deny = args.deny !== undefined ? args.deny : {}
          var params = {
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
          policyName: util.format("policy-%s", clientId)
        };
        console.log(params.policyDocument)

        this.awsIot.createPolicy(params, (err, data) => {
          if (err) {
            return callback ? callback(err) : reject(err);
          }
          const result = {
            policyData: policyData,
            policy: data
          };
          return callback ? callback(null, result) : resolve(result);
        });
      })
    });
  }

  createAndAttachPolicy(args, certificateArn, callback) {
    args = args || {};

    return new Promise((resolve, reject) => {
      // createPolicy
      this.createPolicy(args, (err, result) => {
        if (err) {
          return callback ? callback(err) : reject(err);
        }

        // attachPolicy
        var params = {
          policyName: result.policy.policyName,
          target: certificateArn
        };
        this.awsIot.attachPolicy(params, (err, response) => {
          if (err) {
            return callback ? callback(err) : reject(err);
          }
          const data = {
            policy: result.policy,
            policyData: result.policyData
          };
          return callback ? callback(null, data) : resolve(data);
        });
      });
    });
  }

  createPrincipal(args, callback) {
    args = args || {};

    return new Promise((resolve, reject) => {
      // createKeysAndCertificate
      var params = {
        setAsActive: true
      };
      this.awsIot.createKeysAndCertificate(params).promise()
        .then((result) => {
          this.createAndAttachPolicy(args, result.certificateArn, (err, data) => {
            if (err) {
              return callback ? callback(err) : reject(err);
            }
            data.keyPair = result.keyPair;
            data.certificateArn = result.certificateArn;
            data.certificatePem = result.certificatePem;
            return callback ? callback(null, data) : resolve(data);
          });
        })
        .catch((err) => {
          return callback ? callback(err) : reject(err);
        })
    });
  }

  thingArgs(args) {
    args = args || {};
    args.serialNumber = args.serialNumber !== undefined ? args.serialNumber : "SN-" + crypto.randomBytes(Math.ceil(12 / 2)).toString('hex').slice(0, 15).toUpperCase();
    args.clientId = args.clientId !== undefined ? args.clientId : crypto.randomBytes(Math.ceil(12 / 2)).toString('hex').slice(0, 12).toUpperCase();
    args.thingName = args.thingName !== undefined ? args.thingName : "mht-" + args.clientId;
    args.allow = args.allow !== undefined ? args.allow : {}
    args.deny = args.deny !== undefined ? args.deny : {}
    return args;
  }

  createAndAttachThingPrincipal(args, certificateArn, callback) {
    args = this.thingArgs(args);

    // createThing
    var params = {
      thingName: args.thingName,
      attributePayload: {
        attributes: {
          'clientId': args.clientId,
        },
      },
      // merge: true
    };
    return this.awsIot.createThing(params).promise()
      .then((result) => {
        // attachThingPrincipal
        var params = {
          principal: certificateArn,
          thingName: result.thingName
        };
        return this.awsIot.attachThingPrincipal(params).promise()
          .then((response) => {
            const data = {
              clientId: args.clientId,
              certificateArn: certificateArn,
              thing: result,
              response: response
            };

            return callback ? callback(null, data) : resolve(data);
          })
      })
      .catch((err) => {
        return callback ? callback(err) : reject(err);
      })
  }

  createAndActiveThing(args, callback) {
    args = this.thingArgs(args);

    return new Promise((resolve, reject) => {
      var params = {
        thingName: args.thingName,
        clientId: args.clientId,
        allow: args.allow,
        deny: args.deny
      };
      const principal = this.createPrincipal(params)

      // createThing
      var params = {
        thingName: args.thingName,
        attributePayload: {
          attributes: {
            'clientId': args.clientId,
          },
        },
        // merge: true
      };
      const thing = this.awsIot.createThing(params).promise();

      // wait for thing & principal
      return Promise.all([principal, thing])
        .then((result) => {

          // attachThingPrincipal
          var params = {
            principal: result[0].certificateArn,
            thingName: result[1].thingName
          };
          return this.awsIot.attachThingPrincipal(params).promise()
            .then((response) => {
              const data = {
                clientId: args.clientId,
                principal: result[0],
                thing: result[1],
                response: response
              };

              return callback ? callback(null, data) : resolve(data);
            })
        })
        .catch((err) => {
          return callback ? callback(err) : reject(err);
        })
    });
  }
}

module.exports = Iot;;