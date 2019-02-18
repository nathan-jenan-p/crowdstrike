let async = require('async');
let config = require('./config/config');
let request = require('request');

let detects = require('./detects');
let devices = require('./devices');
let deviceCount = require('./deviceCount');
let iocs = require('./iocs');

let uuid = require('uuid/v4');

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

function searchDetects(token, entity, callback) {
    Logger.trace('searching detects');

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
            callback(err);
            return;
        }

        callback(null, {
            entity: entity,
            ids: body.resources.map(resource => {
                resource.__polarityType = 'detect';
                return resource;
            })
        });
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

function getDetects(token, entityWithIds, callback) {
    Logger.trace('getting detects');

    let results = [];

    let ids = entityWithIds.ids;

    if (ids.length === 0) {
        callback(null, null);
        return;
    }

    requestWithDefaults({
        uri: 'https://api.crowdstrike.com/detects/entities/summaries/GET/v1',
        headers: {
            'authorization': 'bearer ' + token
        },
        body: {
            ids: ids
        },
        json: true,
        method: 'POST'
    }, 200, (err, body) => {
        if (err) {
            callback(err);
            return;
        }

        let matchingResults = body.resources.filter(resource => entityWithIds.ids.includes(resource.detection_id));

        if (matchingResults.length === 0) {
            results.push({
                entity: entityWithId.entity,
                data: null
            });
        } else {
            results.push(matchingResults.map(result => {
                let split = result.detection_id.split(':');
                result.__url = `https://falcon.crowdstrike.com/activity/detections/detail/${split[1]}/${split[2]}`;
                result.open = false;
                result.__id = uuid();
                return result;
            }));
        }

        callback(null, results);
    });
}

function generateAccessToken(options, callback) {
    Logger.trace('generating access token');

    if (options.fakeData) {
        callback(null, 'fake token');
        return;
    }

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

function lookupDetects(token, entity, options) {
    return (callback) => {
        if (!options.lookupDetects) {
            callback();
            return;
        }

        if (options.fakeData) {
            callback(null, detects.resources.map(resource => {
                resource.__isDetects = true;
                resource.open = false;
                resource.__id = uuid();
                return resource;
            }));
        } else {
            searchDetects(token, entity, (err, entityWithIds) => {
                if (err) {
                    callback(err);
                    return;
                }

                getDetects(token, entityWithIds, (err, results) => {
                    if (err) {
                        callback(err);
                        return;
                    }

                    callback(null, results);
                });
            });
        }
    }
}

function lookupDevices(token, entity, options) {
    return (callback) => {
        if (!options.lookupDevices) {
            callback();
            return;
        }

        if (options.fakeData) {
            callback(null, devices.resources.map(resource => {
                resource.__isDevice = true;
                resource.open = false;
                resource.__id = uuid();
                return resource;
            }));
        } else {
            if (entity.isIP || entity.isDomain || entity.isHash) {
                requestWithDefaults({
                    uri: 'https://falconapi.crowdstrike.com/devices/queries/devices/v1',
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
                        callback(err);
                        return;
                    }

                    // TODO when I get crowdstrike access see if this can be done in 1 request
                    let results = [];
                    async.each(body.resources, (id, done) => {
                        requestWithDefaults({
                            uri: 'https://falconapi.crowdstrike.com/devices/entities/devices/v1',
                            headers: {
                                'authorization': 'bearer ' + token
                            },
                            qs: {
                                ids: id
                            },
                            json: true,
                            method: 'GET'
                        }, 200, (err, body) => {
                            if (err) {
                                callback(err);
                                return;
                            }

                            results = results.concat(body.resources);
                            done();
                        });
                    }, err => {
                        callback(err, results);
                    });
                });
            } else {
                callback(null, null);
                return;
            }
        }
    };
}

function lookupDeviceCount(token, entity, options) {
    return (callback) => {
        if (!options.lookupDeviceCount) {
            callback();
            return;
        }

        if (options.fakeData) {
            callback(null, deviceCount.resources.map(resource => {
                resource.__isDeviceCount = true;
                resource.open = false;
                resource.__id = uuid();
                return resource;
            }));
        } else {
            if (entity.isIP || entity.isDomain || entity.isHash) {
                requestWithDefaults({
                    uri: 'https://falconapi.crowdstrike.com/indicators/aggregates/devices-count/v1',
                    headers: {
                        'authorization': 'bearer ' + token
                    },
                    qs: {
                        type: entity.type.toLowerCase(),
                        value: entity.value
                    },
                    json: true,
                    method: 'GET'
                }, 200, (err, body) => {
                    if (err) {
                        callback(err);
                        return;
                    }

                    callback(null, body.resources);
                });
            } else {
                callback(null, null);
                return;
            }
        }
    };
}

function lookupIocs(token, entity, options) {
    return (callback) => {
        if (!options.lookupIocs) {
            callback();
            return;
        }

        if (options.fakeData) {
            callback(null, iocs.resources.map(resource => {
                resource.__isIocs = true;
                resource.open = false;
                resource.__id = uuid();
                return resource;
            }));
        } else {
            if (entity.isIP || entity.isDomain || entity.isHash) {
                requestWithDefaults({
                    uri: 'https://falconapi.crowdstrike.com/indicators/entities/iocs/v1',
                    headers: {
                        'authorization': 'bearer ' + token
                    },
                    qs: {
                        ids: `${entity.type.toLowerCase()}:${entity.value}`
                    },
                    json: true,
                    method: 'GET'
                }, 200, (err, body) => {
                    if (err) {
                        callback(err);
                        return;
                    }

                    callback(null, body.resource);
                });
            } else {
                callback(null, null);
                return;
            }
        }
    };
}

function flattenArray(array) {
    return array.reduce((prev, next) => prev.concat(next), []);
}

function doLookup(entities, options, callback) {
    Logger.trace('starting lookup');
    Logger.trace('options', options);

    let results = [];

    generateAccessToken(options, (err, token) => {
        if (err) {
            callback(err);
            return;
        }

        async.each(entities, (entity, callback) => {
            async.parallel(
                [
                    lookupDetects(token, entity, options),
                    lookupDevices(token, entity, options),
                    lookupDeviceCount(token, entity, options),
                    lookupIocs(token, entity, options)
                ],
                (err, lookups) => {
                    if (err) {
                        callback(err);
                        return;
                    }

                    lookups = lookups.filter(lookup => !!lookup);
                    if (lookups.length === 0) {
                        callback(null, {
                            entity: entity,
                            data: null
                        });
                        return;
                    }

                    lookups = flattenArray(lookups);

                    Logger.trace('lookups', lookups);

                    let tags = flattenArray(lookups.map(lookup => {
                        if (lookup.__isDetects) {
                            return [
                                lookup.status,
                                lookup.max_severity_displayname
                            ];
                        } else if (lookup.__isDevice) {
                            return [
                                lookup.platform_name,
                                lookup.status
                            ];
                        } else if (lookup.__isDeviceCount) {
                            return [
                                `Device Count: ${lookup.device_count}`
                            ];
                        } else if (lookup.__isIocs) {
                            return [
                                lookup.share_level,
                                lookup.policy
                            ];
                        } else {
                            // this case is for when new lookups are added but
                            // there are no tags or the developer forgets
                            return [];
                        }
                    }));

                    results.push({
                        entity: entity,
                        data: {
                            summary: tags,
                            details: lookups
                        }
                    });

                    callback(null);
                });
        }, err => {
            Logger.trace('sending results to client', { results: results });

            callback(err, results);
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
