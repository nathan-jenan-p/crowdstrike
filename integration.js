let async = require('async');
let config = require('./config/config');
let request = require('request');

let Logger;
let requestWithDefaults;
let requestOptions = {};

function handleRequestError(request) {
    return (options, expectedStatusCode, callback) => {
        return request(options, (err, resp, body) => {
            if (err || resp.statusCode !== expectedStatusCode) {
                Logger.error(`error during http request to ${options.uri}`, { error: err, status: resp ? resp.statusCode : 'unknown' });
                callback({ error: err, statusCode: resp ? resp.statusCode : 'unknown' });
            } else {
                callback(null, body);
            }
        });
    };
}

function searchDetects(token, entities, callback) {
    Logger.trace('searching detects');

    let entitiesWithIds = [];

    async.forEach(entities, (entity, done) => {
        requestWithDefaults({
            uri: 'https://api.crowdstrike.com/detects/queries/detects/v1',
            headers: {
                'authorization': 'bearer ' + token
            },
            qs: {
                q: entity.value
            },
            json: true,
            method: 'GET'
        }, 200, (err, body) => {
            if (err) {
                done(err);
                return;
            }

            entitiesWithIds.push({
                entity: entity,
                ids: body.resources
            });
            done(null);
        });
    }, err => {
        if (err) {
            callback(err);
            return;
        }

        callback(null, entitiesWithIds);
    });
}

function dedup(array) {
    let temp = {};

    array.forEach(item => {
        temp[item] = true;
    });

    let deduped = [];

    for (let key in temp) {
        deduped.push(key);
    }

    return deduped;
}

function getDetects(token, entitiesWithIds, callback) {
    Logger.trace('getting detects');

    let results = [];

    let allIds = entitiesWithIds
        .map(entity => entity.ids)
        .reduce((previous, next) => previous.concat(next), []);

    if (allIds.length === 0) {
        entitiesWithIds.forEach(entityWithId => {
            results.push({
                entity: entityWithId.entity,
                data: null
            });
        });

        callback(null, results);
        return;
    }

    requestWithDefaults({
        uri: 'https://api.crowdstrike.com/detects/entities/summaries/GET/v1',
        headers: {
            'authorization': 'bearer ' + token
        },
        body: {
            ids: allIds
        },
        json: true,
        method: 'POST'
    }, 200, (err, body) => {
        if (err) {
            callback(err);
            return;
        }

        entitiesWithIds.forEach(entityWithId => {
            let matchingResults = body.resources.filter(resource => entityWithId.ids.includes(resource.detection_id));

            if (matchingResults.length === 0) {
                results.push({
                    entity: entityWithId.entity,
                    data: null
                });
            } else {
                results.push({
                    entity: entityWithId.entity,
                    data: {
                        summary: dedup(matchingResults
                            .map(result => {
                                return [
                                    result.status,
                                    result.max_severity_displayname
                                ]
                            })
                            .reduce((prev, next) => prev.concat(next), [])),
                        details: matchingResults.map(result => {
                            let split = result.detection_id.split(':');
                            result.__url = `https://falcon.crowdstrike.com/activity/detections/detail/${split[1]}/${split[2]}`;
                            result.open = false;
                            return result;
                        })
                    }
                });
            }
        });

        callback(null, results);
    });
}

function generateAccessToken(options, callback) {
    Logger.trace('generating access token');

    requestWithDefaults({
        uri: 'https://api.crowdstrike.com/oauth2/token',
        method: 'POST',
        json: true,
        form: {
            client_id: options.id,
            client_secret: options.secret
        }
    }, 201, (err, body) => {
        if (err) {
            callback(err);
            return;
        }

        callback(null, body.access_token);
    });
}

function doLookup(entities, options, callback) {
    Logger.trace('starting lookup');

    let results = [];

    generateAccessToken(options, (err, token) => {
        if (err) {
            callback(err);
            return;
        }

        searchDetects(token, entities, (err, entitiesWithIds) => {
            if (err) {
                callback(err);
                return;
            }

            getDetects(token, entitiesWithIds, (err, results) => {
                if (err) {
                    callback(err);
                    return;
                }

                Logger.trace('sending results to client', { results: results });

                callback(null, results);
            });
        });
    });
}

function startup(logger) {
    Logger = logger;

    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
        requestOptions.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
        requestOptions.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
        requestOptions.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
        requestOptions.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
        requestOptions.proxy = config.request.proxy;
    }

    if (typeof config.request.rejectUnauthorized === 'boolean') {
        requestOptions.rejectUnauthorized = config.request.rejectUnauthorized;
    }

    requestOptions.json = true;

    requestWithDefaults = handleRequestError(request.defaults(requestOptions));
}

function validateStringOption(errors, options, optionName, errMessage) {
    if (typeof options[optionName].value !== 'string' ||
        (typeof options[optionName].value === 'string' && options[optionName].value.length === 0)) {
        errors.push({
            key: optionName,
            message: errMessage
        });
    }
}

function validateOptions(options, callback) {
    let errors = [];

    // Example of how to validate a string option
    validateStringOption(errors, options, 'id', 'You must provide a Client ID.');
    validateStringOption(errors, options, 'secret', 'You must provide a Client Secret.');

    callback(null, errors);
}

module.exports = {
    doLookup: doLookup,
    startup: startup,
    validateOptions: validateOptions
};
