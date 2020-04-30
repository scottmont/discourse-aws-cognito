var AWS = require('aws-sdk')
const jwt = require('jsonwebtoken')

function checkuser(token){
    return new Promise(function(resolve, reject) {
     parsejson = jwt.decode(token)
        var params = {
          AccessToken: token,
         }
        var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider({'region': 'us-east-1'});
        cognitoidentityserviceprovider.getUser(params, function (err, data) {
        if (err) {
            reject(err);
        } 
        else   {      
            data.iss = parsejson.iss
            let email = data.UserAttributes.filter(it => it.Name.includes('email') && it.Name.length < 6 );
            data.email = email[0].Value
            let name = data.UserAttributes.filter(it => it.Name.includes('name') && it.Name.length < 5);
            data.name = name[0] ? name[0].Value : ''
            let picture = data.UserAttributes.filter(it => it.Name.includes('picture') );
            data.picture = picture[0] ? picture[0].Value : ''
            let email_verified = data.UserAttributes.filter(it => it.Name.includes('email_verified'));
            data.email_verified = email_verified[0] ? email_verified[0].Value : ''
            data.exp = parsejson.exp
            data.iat = parsejson.iat
            data.auth_time  = parsejson.auth_time
            resolve(data)
        }  
        });
    });
    
}

function _getSecrets (req, callback) {
  client = new AWS.SecretsManager({
      region: region
    });
  client.getSecretValue({SecretId: req.query.client_id}, function(err, data) {
    

    if (err) {
        if (err.code === 'DecryptionFailureException')
            // Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
        else if (err.code === 'InternalServiceErrorException')
            // An error occurred on the server side.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
        else if (err.code === 'InvalidParameterException')
            // You provided an invalid value for a parameter.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
        else if (err.code === 'InvalidRequestException')
            // You provided a parameter value that is not valid for the current state of the resource.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
        else if (err.code === 'ResourceNotFoundException')
            // We can't find the resource that you asked for.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
        
    }
    else {
      console.log(err);
      
        // Decrypts secret using the associated KMS CMK.
        // Depending on whether the secret is a string or binary, one of these fields will be populated.
        if ('SecretString' in data) {
            secret = data.SecretString;
            callback(secret)
        } else {
            let buff = new Buffer(data.SecretBinary, 'base64');
            decodedBinarySecret = buff.toString('ascii');
            callback(decodedBinarySecret)
           
        }
        
        
    }

  });
}

// One time initialisation to download the JWK keys and convert to PEM format. Returns a promise.
function _init (secrets) {
  return new Promise((resolve, reject) => {
    var useSecret = JSON.parse(secrets)
    const ISSUER = `https://cognito-idp.${useSecret.region}.amazonaws.com/${useSecret.userPool}`
    const options = {
      url: `${ISSUER}/.well-known/jwks.json`,
      json: true
    }
    request.get(options, function (err, resp, body) {
      if (err) {
        console.debug(`Failed to download JWKS data. err: ${err}`)
        reject(new Error('Internal error occurred downloading JWKS data.')) // don't return detailed info to the caller
        return
      }
      if (!body || !body.keys) {
        console.debug(`JWKS data is not in expected format. Response was: ${JSON.stringify(resp)}`)
        reject(new Error('Internal error occurred downloading JWKS data.')) // don't return detailed info to the caller
        return
      }
      const pems = {}
      for (let i = 0; i < body.keys.length; i++) {
        pems[body.keys[i].kid] = jwkToPem(body.keys[i])
      }
      console.info(`Successfully downloaded ${body.keys.length} JWK key(s)`)
      
      resolve(pems)
    })
  })
}


function _getVerifyMiddleware () {
  
  _getSecrets(req, function(secrets) {
    console.log('here');
    
    const pemsDownloadProm = _init(secrets)
    .catch((err) => {
      return { err }
    })
    pemsDownloadProm.then((pems) => {
      console.log('pemsdl')
      return _getIdToken(pems, secrets, req)
    })
    .then((decoded) => {
      return checkuser(decoded) 
    })
    .then((data) => {

        req.json = {
          "azp": "2020.custom",
          "aud": "2020.custom",
          "sub": data.Username,
          "email": data.email,
          "email_verified": data.email_verified,
          "at_hash": data.auth_time,
          "name": data.name,
          "picture": data.picture,
          "exp": data.exp,
          "iss": data.iss,
          "iat": data.iat,
          "alg": "RS256"
        }
        console.log(req.json)
        next()
      })
  }
  )}


exports.getVerifyMiddleware = _getVerifyMiddleware
