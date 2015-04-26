"use strict";

var jwt = require('jwt-simple');
var annotator = require('annotator');
var _t = annotator.util.gettext;

function TokenIdentityPolicy (token) {
    this.token = token;
}
 
TokenIdentityPolicy.prototype.who = function () {
    return this.token;
};

TokenIdentityPolicy.prototype.setToken = function (token) {
    this.token = token;
    this.payload = jwt.decode(token, null, false);
}
 

function TokenAuthzPolicy () {
    annotator.authz.AclAuthzPolicy.call(this);
}

TokenAuthzPolicy.prototype = Object.create(annotator.authz.AclAuthzPolicy.prototype);
TokenAuthzPolicy.prototype.constructor = annotator.authz.AclAuthzPolicy;

TokenAuthzPolicy.prototype.authorizedUserId = function (identity) {
    var payload = jwt.decode(identity, null, false);
    return payload.userId;
};

 
var tokenauth = function (options) {
    options = options || {
        token: null,
        tokenUrl: '/auth/token',
        autoFetch: true
    };
    
    var identityPolicy = new TokenIdentityPolicy(options.token);
    var authorizationPolicy = new TokenAuthzPolicy();
    var notify = console.log;
    
    var fetchToken = function() {
        return $.ajax({
            url: options.tokenUrl,
            dataType: 'text',
            xhrFields: {
                withCredentials: true
            }
        }).fail(function(xhr, status, err) {
            var msg;
            msg = _t("Couldn't get auth token:");
            console.error("" + msg + " " + err, xhr);
            return notify("" + msg + " " + xhr.responseText, annotator.notification.ERROR);
        });
    };

    var haveValidToken = function() {
        var payload = identityPolicy.payload;
        var allFields = payload && payload.issuedAt && payload.ttl && payload.consumerKey;
        if (allFields) {
            return true;
        } else {
            return false;
        }
    };
    
    return {
        configure: function (registry) {
            registry.registerUtility(identityPolicy, 'identityPolicy');
            registry.registerUtility(authorizationPolicy, 'authorizationPolicy');
        },
        
        start: function (app) {
            notify = app.registry.queryUtility('notifier') || notify;
            if (!options.token) {
                return fetchToken(options.tokenUrl).then(function (tok) { 
                    identityPolicy.setToken(tok);
                });
            }
        }
    };
};
 
// app.include(...tokenauth, {token: 'ABCDE'})
//
// OR
//
// app.include(...tokenauth, {tokenUrl: '/auth/token'})
// app
// .start()
// .then(function () {
//     app.annotations.store.setHeader('X-Annotator-Auth-Token', app.ident.token);
// })

