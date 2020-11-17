const path = require('path');
 module.exports = {
   entry: {
     "sncrypto-common.js": "./lib/common/index",
     "sncrypto-web.js": "./lib/web/index",
   },
   resolve: {
     extensions: ['.ts', '.js']
   },
   output: {
     path: path.resolve(__dirname, 'dist'),
     filename: './[name]',
     chunkFilename: '[name].bundle.js',
     library: 'SNCrypto',
     libraryTarget: 'umd',
     umdNamedDefine: true,
     publicPath: '/dist/'
   },
   optimization: {
     minimize: false,
   },
   module: {
     rules: [
       {
         test: /\.ts(x?)$/,
         exclude: /node_modules/,
         use: [
           { loader: 'babel-loader' },
           { loader: 'ts-loader' }
         ]
       },
       {
         test: /\.(js)$/,
         loader: 'babel-loader',
       }
     ]
   },
   plugins: [],
   stats: {
     colors: true
   },
   devtool: 'source-map'
 };
