const path = require('path');

module.exports = {
  entry: {
    "sncrypto.js": "./lib/main.js",
    "sncrypto.min.js": "./lib/main.js"
  },
  resolve: {
    alias: {
      "@Root": path.resolve(__dirname, "."),
      "@Lib": path.resolve(__dirname, "lib"),
      "@Crypto": path.resolve(__dirname, "lib/crypto")
    }
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: './[name]',
    library: 'SNCrypto',
    libraryTarget: 'umd',
    umdNamedDefine: true,
    publicPath: '/dist/'
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        loader: 'babel-loader',
      }
    ]
  },
  stats: {
    colors: true
  },
  devtool: 'source-map'
};
