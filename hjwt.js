const base64url = require('base64url');
const crypto = require('crypto');
const fs = require("fs");


/**
 * @typedef {Object} Payload
 * @param {Payload} payload - it should be an object
 * @param {String} privateKey - pem file /utf-8 encoding
 * @param {String} passphrase  
 * @param {Number} expiresInMinutes  
 * @returns 
 */
function generateJWTToken(payload, privateKey, passphrase,expiresInMinutes) {
    const header = {
      "alg": "RS256",
      "typ": "JWT"
    };


  payload = {...payload, exp:(Date.now()+expiresInMinutes*60*1000)}
    const header64 = base64url(JSON.stringify(header));
    const payload64 = base64url(JSON.stringify(payload));
    const presign = `${header64}.${payload64}`;
  
    const signOptions = {
      key: privateKey,
      passphrase: passphrase
    };
  
    const signature = crypto.createSign('RSA-SHA256').update(presign).sign(signOptions, 'base64');
    const signature64url = base64url.fromBase64(signature);
  
    const token = `${presign}.${signature64url}`;
  
    return token;
  }

/**
 * 
 * @param {*} token - JWT Token
 * @param {String} publicKey - pem file/utf-8 encoding
 * @returns 
 */
  function verifyJWTToken(token, publicKey) {
    const [header64, payload64, signature64url] = token.split('.');
  
    const signOptions = {
      key: publicKey,
      algorithms: ['RS256']
    };
  
    const signature = base64url.toBase64(signature64url);
    const presign = `${header64}.${payload64}`;
  
    const isVerified = crypto.createVerify('RSA-SHA256').update(presign).verify(signOptions, signature, 'base64');
  
    if (isVerified) {
      const payload = JSON.parse(base64url.decode(payload64));
      const currentTime = Date.now()
  
      if (payload.exp && payload.exp < currentTime) {

        return { valid: false, message: 'Token date is expired' };
      }

      return { valid: true, payload };
    }
  

    return { valid: false, message: 'Token is unverified' };
  }

  const { generateKeyPairSync, publicEncrypt, privateDecrypt } = require('crypto');
const fs = require('fs');

/**
 * 
 * @param {String} passphrase - key for privatekey
 */
function setup(passphrase) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: passphrase,
    },
  });

  fs.writeFileSync(__dirname + '/pub.pem', publicKey);
  fs.writeFileSync(__dirname + '/priv.pem', privateKey);
}

setup();

/**
 * encrypt data with public key
 * @param {*} data 
 * @returns 
 */
const encryptedData = (data,publicKey)=>publicEncrypt(
  {
    key: publicKey,
  },
  Buffer.from(data)
);

/**
 * 
 * @param {*} data 
 * @param {String} privateKey - utf-8 encoding, pem file
 * @param {String} passphrase 
 * @returns 
 */
const decryptedData =(data,privateKey,passphrase)=> privateDecrypt(
  {
    key: privateKey,
    passphrase: passphrase,
  },
  data
);


module.exports = {encryptedData,decryptedData,setup,generateJWTToken,verifyJWTToken}
  
