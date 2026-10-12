global class Auth0ClientCredentials extends Auth.AuthProviderPluginClass implements Auth.AuthProviderPlugin {

    global String getCustomMetadataType() {
        return 'Auth0_OAuth_Config__mdt';
    }

    global PageReference initiate(Map<String,String> config, String stateToPropagate) {
        // config.get('callbackUrl') is null for Custom provider type, so build it
        // explicitly. Format: <orgBaseUrl>/services/authcallback/<DeveloperName>
        String callbackUrl = URL.getOrgDomainUrl().toExternalForm()
            + '/services/authcallback/Auth0_POC';
        PageReference ref = new PageReference(callbackUrl);
        ref.getParameters().put('code', 'client_credentials');
        ref.getParameters().put('state', stateToPropagate);
        return ref;
    }

    global Auth.AuthProviderTokenResponse handleCallback(
            Map<String,String> config, Auth.AuthProviderCallbackState state) {
        String accessToken = fetchToken(config);
        return new Auth.AuthProviderTokenResponse(
            'Auth0', accessToken, accessToken,
            state.queryParameters.get('state')
        );
    }

    global override Auth.OAuthRefreshResult refresh(Map<String,String> config, String refreshToken) {
        String accessToken = fetchToken(config);
        if (accessToken != null) {
            return new Auth.OAuthRefreshResult(accessToken, accessToken, null);
        }
        return new Auth.OAuthRefreshResult(null, null, 'Token request failed');
    }

    global Auth.UserData getUserInfo(Map<String,String> config,
            Auth.AuthProviderTokenResponse response) {
        // Named Credential flow still resolves getUserInfo(); return the executionUser
        // so Salesforce can map the identity to a real user in the org.
        return new Auth.UserData(
            'm2jakkula@gmail.com',
            null, null, null,
            'm2jakkula@gmail.com',
            null,
            'm2jakkula@gmail.com',
            null, 'Auth0', null,
            new Map<String,String>()
        );
    }

    private String fetchToken(Map<String,String> config) {
        HttpRequest req = new HttpRequest();
        req.setEndpoint(config.get('Token_URL__c'));
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
        req.setBody(
            'grant_type=client_credentials' +
            '&client_id='     + EncodingUtil.urlEncode(config.get('Client_Id__c'), 'UTF-8') +
            '&client_secret=' + EncodingUtil.urlEncode(config.get('Client_Secret__c'), 'UTF-8') +
            '&audience='      + EncodingUtil.urlEncode(config.get('Audience__c'), 'UTF-8')
        );
        HttpResponse res = new Http().send(req);
        if (res.getStatusCode() == 200) {
            Map<String,Object> body = (Map<String,Object>) JSON.deserializeUntyped(res.getBody());
            return (String) body.get('access_token');
        }
        return null;
    }
}
