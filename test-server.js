// Used for running mocha tests

var connect = require('connect');
var serveStatic = require('serve-static');
connect().use(serveStatic(__dirname)).listen(9003, function(){
    console.log('Server running on 9003...');
});
