const fs = require('fs');
const forge = require('node-forge');

function createCertificateFromKeys(args, privateKey, publicKey) {
    // openssl req -x509 -new -nodes -key caKey.pem -sha256 -days 36500 -out caCert.pem
    const pki = forge.pki;

    const cert = pki.createCertificate();

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

    var extensions = args.extensions;
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
    const pki = forge.pki;

    const csr = pki.createCertificationRequest();

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
    const cert = forge.pki.createCertificate();

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
    const pki = forge.pki;

    // openssl genrsa -out caKey.pem 2048
    pki.rsa.generateKeyPair(2048, function (err, keys) {

        if (err) {
            return callback(err);
        }
        const cert = createCertificateFromKeys(args, keys.privateKey, keys.publicKey);
        callback(null, { caCert: cert, caKey: keys.privateKey });
    })
}

function createCAFromPem(args, pem) {
    const pki = forge.pki;

    const privateKey = pki.privateKeyFromPem(pem)
    const publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e);
    const cert = createCertificateFromKeys(args, privateKey, publicKey);
    return { caCert: cert, caKey: privateKey };
}

function createCAFromPemFile(args, pemFile, callback) {
    fs.readFile(pemFile, function (err, data) {
        if (err) {
            return callback(err);
        }
        const result = createCAFromPem(args, data);

        callback(null, result);
    });
}

function createCertificateSigningRequest(args, callback) {
    const pki = forge.pki;

    // openssl genrsa -out verificationCert.key 2048
    pki.rsa.generateKeyPair(2048, function (err, keys) {
        if (err) {
            return callback(err);
        }

        const csr = createCertificateSigningRequestFromKeys(args, keys.privateKey, keys.publicKey);

        callback(null, {csr: csr, keys: keys});
    });
}

function createCertificateSigningRequestFromPem(args, pem) {
    const pki = forge.pki;

    const privateKey = pki.privateKeyFromPem(pem)
    const publicKey = pki.setRsaPublicKey(privateKey.n, privateKey.e);
    return createCertificateSigningRequestFromKeys(args, privateKey, publicKey);
}

function createCertificateSigningRequestFromPemFile(args, pemFile, callback) {
    fs.readFile(pemFile, function (err, data) {
        const result = createCertificateSigningRequestFromPem(args, data, callback);

        callback(null, result);
    });
}

function createVerificationCertificateFromCA(args, caCert, caKey, callback) {
    createCertificateSigningRequest(args, function (err, data) {
        if (err) {
            return callback(err);
        }

        // const verified = csr.verify();
        // console.log(verified);

        const cert = createCertificateFromCertificateSigningRequest(args, data.csr, caCert, caKey);
        callback(null, {cert: cert, keys: data.keys});
    });
}

function createVerificationCertificateFromCAPem(args, pemCert, pemKey, callback) {
    createCertificateSigningRequest(args, function (err, data) {
        if (err) {
            return callback(err);
        }
        const pki = forge.pki;

        const caCert = certificateFromPem(pemCert);
        const caKey = pki.privateKeyFromPem(pemKey)

        const cert = createCertificateFromCertificateSigningRequest(args, data.csr, caCert, caKey);
        callback(null, {cert: cert, keys: data.keys});
    });
}

module.exports.createCertificateSigningRequest = createCertificateSigningRequest;
module.exports.createCACertificate = createCACertificate;
module.exports.createCAFromPem = createCAFromPem;
module.exports.createCAFromPemFile = createCAFromPemFile;
module.exports.createCertificateFromCertificateSigningRequest = createCertificateFromCertificateSigningRequest;
module.exports.createVerificationCertificateFromCA = createVerificationCertificateFromCA;