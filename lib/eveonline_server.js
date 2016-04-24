var OAuth = Package.oauth.OAuth;
var urlUtil = Npm.require('url');

var getTokenResponse = function(query) {
    var config = ServiceConfiguration.configurations.findOne({service: 'eveonline'});

    if (!config) {
        throw new ServiceConfiguration.ConfigError('Service not configured');
    }

    var responseContent;
    try {
        responseContent = Meteor.http.post(config.isTest ? 'https://sisilogin.testeveonline.com/oauth/token' : 'https://login.eveonline.com/oauth/token', {params: {
            grant_type: 'authorization_code',
            code: query.code,
            client_id: config.clientId,
            client_secret: OAuth.openSecret(config.secret),
            redirect_uri: encodeURIComponent(Meteor.absoluteUrl('_oauth/eveonline?close'))
        }}).content;
    } catch (exception) {
        throw new Error('Failed to complete OAuth handshake\n\n' + exception.message);
    }

    var parsedResponse;
    try {
        parsedResponse = JSON.parse(responseContent);
    } catch (exception) {
        throw new Error('Failed to complete OAuth handshake\n\n' + responseContent);
    }

    if (!parsedResponse.access_token) {
        throw new Error('Failed to complete OAuth handshake, did not receive an oauth token.\n\n' + responseContent);
    }

    return {
        accessToken: parsedResponse.access_token,
        expiresIn: parsedResponse.expires_in,
        refreshToken: parsedResponse.refresh_token
    };
};

var getVerification = function(accessToken) {
    var config = ServiceConfiguration.configurations.findOne({service: 'eveonline'});

    if (!config) {
        throw new ServiceConfiguration.ConfigError('Service not configured');
    }

    try {
        return Meteor.http.get(config.isTest ? 'https://sisilogin.testeveonline.com/oauth/verify' : 'https://login.eveonline.com/oauth/verify', {
            headers: {
                Authorization: 'Bearer ' + accessToken
            }
        }).data;
    } catch (exception) {
        throw new Error('Failed to verify with EvE login server.\n\n' + exception.message);
    }
};

OAuth.registerService('eveonline', 2, null, function(query) {
    var response = getTokenResponse(query);
    var verificaton = getVerification(response.accessToken);

    return {
        serviceData: {
            id: verificaton.CharacterOwnerHash,
            accessToken: response.accessToken,
            refreshToken: response.refreshToken,
            expiresAt: +new Date + 1000 * response.expiresIn
        },
        options: {
            profile: {
                eveOnlineCharacterId: verificaton.CharacterID,
                eveOnlineCharacterName: verificaton.CharacterName
            }
        }
    };
});

Eveonline.retrieveCredential = function(credentialToken, credentialSecret) {
    return OAuth.retrieveCredential(credentialToken, credentialSecret);
};
