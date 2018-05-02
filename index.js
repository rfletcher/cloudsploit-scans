var async = require('async');
var AWS = require('aws-sdk');
var plugins = require('./exports.js');
var collector = require('./collect.js');

AWS.config = new AWS.Config({
    // credentials: {
    //     accessKeyId: '',
    //     secretAccessKey: '',
    //     sessiontoken: ''
    // },
    // region: ''
});

var skipRegions = [];   // Add any regions you wish to skip here. Ex: 'us-east-2'

// Custom settings - place plugin-specific settings here
var settings = {};

// Determine if scan is a compliance scan
var COMPLIANCE;

if (process.argv.join(' ').indexOf('--compliance') > -1) {
    if (process.argv.join(' ').indexOf('--compliance=hipaa') > -1) {
        COMPLIANCE='hipaa';
        console.log('INFO: Compliance mode: HIPAA');
    } else {
        console.log('ERROR: Unsupported compliance mode. Please use one of the following:');
        console.log('       --compliance=hipaa');
        process.exit();
    }
}

// STEP 1 - Obtain API calls to make
console.log('INFO: Determining API calls to make...');

var apiCalls = [];

for (p in plugins) {
    for (a in plugins[p].apis) {
        if (apiCalls.indexOf(plugins[p].apis[a]) === -1) {
            if (COMPLIANCE) {
                if (plugins[p].compliance && plugins[p].compliance[COMPLIANCE]) {
                    apiCalls.push(plugins[p].apis[a]);
                }
            } else {
                apiCalls.push(plugins[p].apis[a]);
            }
        }
    }
}

console.log('INFO: API calls determined.');
console.log('INFO: Collecting AWS metadata. This may take several minutes...');

// STEP 2 - Collect API Metadata from AWS
collector({api_calls: apiCalls, skip_regions: skipRegions}, function(err, collection){
    if (err || !collection) return console.log('ERROR: Unable to obtain API metadata');

    console.log('INFO: Metadata collection complete. Analyzing...');
    console.log('INFO: Analysis complete. Scan report to follow...\n');

    async.forEachOfLimit(plugins, 10, function(plugin, key, callback){
        if (COMPLIANCE && (!plugin.compliance || !plugin.compliance[COMPLIANCE])) {
            return callback();
        }

        plugin.run(collection, settings, function(err, results){
            if (COMPLIANCE) {
                    console.log('');
                    console.log('-----------------------');
                    console.log(plugin.title);
                    console.log('-----------------------');
                    console.log(plugin.compliance[COMPLIANCE]);
                    console.log('');
                }
            for (r in results) {
                var statusWord;
                if (results[r].status === 0) {
                    statusWord = 'OK';
                } else if (results[r].status === 1) {
                    statusWord = 'WARN';
                } else if (results[r].status === 2) {
                    statusWord = 'FAIL';
                } else {
                    statusWord = 'UNKNOWN';
                }

                console.log(plugin.category + '\t' + plugin.title + '\t' +
                            (results[r].resource || 'N/A') + '\t' +
                            (results[r].region || 'Global') + '\t\t' +
                            statusWord + '\t' + results[r].message);
            }

            setTimeout(function() { callback(err); }, 0);
        });
    }, function(err){
        if (err) return console.log(err);
    });
});
