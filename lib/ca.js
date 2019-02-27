const fs = require('fs');

const crypto = require('crypto');
const forge = require('node-forge')
const util = require('node-forge').util;

function createCertificateFromKeys(args, privateKey, publicKey) {
    // openssl req -x509 -new -nodes -key caKey.pem -sha256 -days 36500 -out caCert.pem
    var pki = forge.pki;

    var cert = pki.createCertificate();

    cert.publicKey = publicKey;
    // alternatively set public key from a csr
    //cert.publicKey = csr.publicKey;
    // NOTE: serialNumber is the hex encoded value of an ASN.1 INTEGER.
    // Conforming CAs should ensure serialNumber is:
    // - no more than 20 octets
    // - non-negative (prefix a '00' if your value starts with a '1' bit)
    args = args || {};
    cert.serialNumber = args.serialNumber !== undefined ? args.serialNumber : '00cc3f3ee26d9a574e';
    if (args.validity === undefined) {
        cert.validity = {
            notBefore: new Date(),
            notAfter: new Date()
        };
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
    }

    var attrs = args.attrs;
    if (attrs === undefined) {
        attrs = [{
            name: 'countryName',
            value: 'VN'
        }, {
            shortName: 'ST',
            value: 'Hanoi'
        }, {
            name: 'localityName',
            value: 'Hanoi'
        }, {
            name: 'organizationName',
            value: 'minhhatech'
        }, {
            shortName: 'OU',
            value: 'MHT'
        }];
    }

    extensions = args.extensions;
    if (extensions === undefined) {
        extensions = [{
            name: 'subjectKeyIdentifier'
        }, {
            name: 'authorityKeyIdentifier',
            keyIdentifier: true,
            authorityCertIssuer: true,
            serialNumber: true
        }, {
            name: 'basicConstraints',
            cA: true
        }];
    }

    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions(extensions);

    // signs a certificate using SHA-256
    cert.sign(privateKey, forge.md.sha256.create());

    return cert;
}

function createCertificateSigningRequestFromKeys(args, privateKey, publicKey) {
    // openssl req -new -key verificationCert.key -out verificationCert.csr
    var pki = forge.pki;

    var csr = pki.createCertificationRequest();

    args = args || {};

    var attrs = args.attrs;

    if (attrs === undefined) {
        attrs = [{
            name: 'countryName',
            value: 'VN'
        }, {
            shortName: 'ST',
            value: 'Hanoi'
        }, {
            name: 'localityName',
            value: 'Hanoi'
        }, {
            name: 'organizationName',
            value: 'minhhatech'
        }, {
            shortName: 'OU',
            value: 'MHT'
        }, {
            name: 'commonName',
            value: 'mht.vn'
        }];
    }

    var attributes = args.attributes;
    if (attributes === undefined) {
        // set (optional) attributes
        attributes = [{
            name: 'challengePassword',
            value: ''
        }, {
            name: 'unstructuredName',
            value: 'MHT, Inc.'
        }, {
            name: 'extensionRequest',
            extensions: [{
                name: 'subjectAltName',
                altNames: [{
                    // 2 is DNS type
                    type: 2,
                    value: 'test.domain.com'
                }, {
                    type: 2,
                    value: 'other.domain.com',
                }, {
                    type: 2,
                    value: 'www.domain.net'
                }]
            }]
        }]
    }

    csr.publicKey = publicKey;

    csr.setSubject(attrs);

    csr.setAttributes(attributes);

    // sign certification request
    csr.sign(privateKey);

    return csr;
}

function createCertificateFromCertificateSigningRequest(args, csr, caCert, caKey) {
    // openssl x509 -req -in verificationCert.csr -CA caCert.pem -CAkey caKey.pem -CAcreateserial -out verificationCert.crt -days 36500 -sha256
    var cert = forge.pki.createCertificate();

    args = args || {};

    cert.serialNumber = args.serialNumber !== undefined ? args.serialNumber : '02';
    if (args.validity === undefined) {
        cert.validity = {
            notBefore: new Date(),
            notAfter: new Date()
        };
        cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);
    }

    cert.setSubject(csr.subject.attributes);

    // console.log(csr.subject);
    // console.log(cert.subject);

    cert.setIssuer(caCert.subject.attributes);

    // extensions = args.extensions;
    // if(extensions === undefined){
    //     extensions = [{
    //         name: 'basicConstraints',
    //         cA: true
    //     }, {
    //         name: 'keyUsage',
    //         keyCertSign: true,
    //         digitalSignature: true,
    //         nonRepudiation: true,
    //         keyEncipherment: true,
    //         dataEncipherment: true
    //     }, {
    //         name: 'subjectAltName',
    //         altNames: [{
    //             type: 6, // URI
    //             value: 'http://example.org/webid#me'
    //         }]
    //     }];
    // }
    // cert.setExtensions(extensions);

    cert.publicKey = csr.publicKey;

    cert.sign(caKey, forge.md.sha256.create());

    return cert;
}

function createCACertificate(args, callback) {
    var pki = forge.pki;

    // openssl genrsa -out caKey.pem 2048
    pki.rsa.generateKeyPair(2048, function (err, keys) {

        if (err) {
            return callback(err);
        }
        var cert = createCertificateFromKeys(args, keys.privateKey, keys.publicKey);
        callback(null, { caCert: cert, caKey: keys.privateKey });
    })
}

function createCAFromPem(args, pem) {
    var pki = forge.pki;

    var privateKey = pki.privateKeyFromPem(pem)
    var publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e);
    var cert = createCertificateFromKeys(args, privateKey, publicKey);
    return { caCert: cert, caKey: privateKey };
}

function createCAFromPemFile(args, pemFile, callback) {
    fs.readFile(pemFile, function (err, data) {
        if (err) {
            return callback(err);
        }
        var result = createCAFromPem(args, data);

        callback(null, result);
    });
}

function createCertificateSigningRequest(args, callback) {
    var pki = forge.pki;

    // openssl genrsa -out verificationCert.key 2048
    pki.rsa.generateKeyPair(2048, function (err, keys) {
        var csr = createCertificateSigningRequestFromKeys(args, keys.privateKey, keys.publicKey);

        callback(null, csr);
    });
}

function createCertificateSigningRequestFromPem(args, pem) {
    var pki = forge.pki;

    var privateKey = pki.privateKeyFromPem(pem)
    var publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e);
    return createCertificateSigningRequestFromKeys(args, privateKey, publicKey);
}

function createCertificateSigningRequestFromPemFile(args, pemFile, callback) {
    fs.readFile(pemFile, function (err, data) {
        var result = createCertificateSigningRequestFromPem(args, data, callback);

        callback(null, result);
    });
}

function createVerificationCertificateFromCA(args, caCert, caKey, callback) {
    createCertificateSigningRequest(args, function (err, csr) {
        if (err) {
            return callback(err);
        }

        // var verified = csr.verify();
        // console.log(verified);

        var cert = createCertificateFromCertificateSigningRequest(args, csr, caCert, caKey);
        callback(null, cert);
    });
}

function createVerificationCertificateFromCAPem(args, pemCert, pemKey, callback) {
    createCertificateSigningRequest(args, function (err, csr) {
        if (err) {
            return callback(err);
        }
        var pki = forge.pki;

        var caCert = certificateFromPem(pemCert);
        var caKeyprivateKey = pki.privateKeyFromPem(pemKey)

        var cert = createCertificateFromCertificateSigningRequest(args, csr, caCert, caKey);
        callback(null, cert);
    });
}

module.exports.createCertificateSigningRequest = createCertificateSigningRequest;
module.exports.createCACertificate = createCACertificate;
module.exports.createCAFromPem = createCAFromPem;
module.exports.createCAFromPemFile = createCAFromPemFile;
module.exports.createCertificateFromCertificateSigningRequest = createCertificateFromCertificateSigningRequest;
module.exports.createVerificationCertificateFromCA = createVerificationCertificateFromCA;