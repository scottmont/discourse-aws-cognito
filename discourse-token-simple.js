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

function _getVerifyMiddleware () {
  return function (req, next) {
    checkuser(req.query.jwt)
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
        }
        console.log(req.json)
        next()
      })
  }
}

exports.getVerifyMiddleware = _getVerifyMiddleware
