const path = require('path');
const webpack = require('webpack');
const CopyWebpackPlugin = require('copy-webpack-plugin');

module.exports = {
    entry: {
      "sncrypto.js": "./lib/main.js",
      "sncrypto.min.js": "./lib/main.js"
    },
    mode: 'production',
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
      umdNamedDefine: true
    },
    optimization: {
      minimize: true,
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
