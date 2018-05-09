'use strict';

require('dotenv').config({ silent: true });
var jwksClient = require('jwks-rsa');
var jwt = require('jsonwebtoken');
var public_urns_re = new RegExp('^arn:aws:execute-api:us-east-1:967417580898:\\w+/prod/\\w+/api/(ballots|results|setups)/');

var getPolicyDocument = function (effect, resource) {

    var policyDocument = {};
    policyDocument.Version = '2012-10-17'; // default version
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = 'execute-api:Invoke'; // default action
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    return policyDocument;
}


// extract and return the Bearer Token from the Lambda event parameters
var getToken = function (params) {
    var token;

    if (!params.type || params.type !== 'TOKEN') {
        throw new Error("Expected 'event.type' parameter to have value TOKEN");
    }

    var tokenString = params.authorizationToken;
    if (!tokenString) {
        throw new Error("Expected 'event.authorizationToken' parameter to be set");
    }

    var match = tokenString.match(/^Bearer (.*)$/);
    if (!match || match.length < 2) {
        throw new Error("Invalid Authorization token - '" + tokenString + "' does not match 'Bearer .*'");
    }
    return match[1];
}

var err_cb = function (err, params, cb) {
    let allow_empty = public_urns_re.test(params.methodArn);
    if (allow_empty) {
        cb(null, {
            principalId: "",
            policyDocument: getPolicyDocument('Allow', params.methodArn),
            context: {
                scope: ""
            }
        });
    } else {
        cb(err);
    }
}

module.exports.authenticate = function (params, cb) {
    console.log(params);

    var token = getToken(params);

    var client = jwksClient({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 10, // Default value
        jwksUri: process.env.JWKS_URI
    });

    var decoded = jwt.decode(token, { complete: true });
    try {
        var kid = decoded.header.kid;
    }
    catch (err) {
        err_cb(err, params, cb);
    }
    client.getSigningKey(kid, function (err, key) {
        if(err) {
            err_cb(err, params, cb);
        } else {
            var signingKey = key.publicKey || key.rsaPublicKey;
            jwt.verify(token, signingKey, { audience: process.env.AUDIENCE, issuer: process.env.TOKEN_ISSUER },
                function (err, decoded) {
                    if (err) {
                        err_cb(err, params, cb);
                    } else {
                        cb(null, {
                            principalId: decoded.sub,
                            policyDocument: getPolicyDocument('Allow', params.methodArn),
                            context: {
                                scope: decoded.scope
                            }
                        });
                    }
            });
        }
    });
}
