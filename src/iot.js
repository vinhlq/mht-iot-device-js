const ca = require('./utils/ca.js');

function createDeviceCertificateArgs(args, commonName, serialNumber) {
  var args = args || {};

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

  return {
    serialNumber: serialNumber,
    attrs: attrs
  };
}

function createDeviceCertificate(args, commonName, serialNumber, caCert, caKey, callback) {
  return new Promise((resolve, reject) => {
    
    ca.createVerificationCertificateFromCA(createDeviceCertificateArgs(args, commonName, serialNumber), caCert, caKey, (err, data) => {
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

function createDeviceCertificateSync(args, commonName, serialNumber, caCert, caKey) {
  return ca.createCertificateFromCASync(createDeviceCertificateArgs(args), caCert, caKey);
}

function createDeviceCertificateFromPemSync(args, commonName, serialNumber, caCert, caKey) {
  return ca.createCertificateFromCAPemSync(createDeviceCertificateArgs(args, commonName, serialNumber), caCert, caKey);
}

module.exports = {
  createDeviceCertificate: createDeviceCertificate,
  createDeviceCertificateSync: createDeviceCertificateSync,
  createDeviceCertificateFromPemSync: createDeviceCertificateFromPemSync
}