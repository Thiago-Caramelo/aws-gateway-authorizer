const jwt = require('jsonwebtoken');

const options = {
    maxAge: process.env.JWT_MAX_AGE || "1d",
    algorithms: ["HS256"],
};

exports.handler = function (event, context, callback) {
    const token = event.authorizationToken;
    console.info(token);
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET, options);
        const user = decoded.assinanteId || decoded.id;
        callback(null, generateIAMPolicy(user, "Allow", event.methodArn));
    } catch (error) {
        console.error(error);
        callback(null, generateIAMPolicy("unknownuser", "Deny", event.methodArn));
    }
};

const generateIAMPolicy = function (principalId, effect, resource) {
    const authResponse = {};

    authResponse.principalId = principalId;
    if (effect && resource) {
        const policyDocument = {};
        policyDocument.Version = "2012-10-17";
        policyDocument.Statement = [];
        const statementOne = {};
        statementOne.Action = "execute-api:Invoke";
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    return authResponse;
}