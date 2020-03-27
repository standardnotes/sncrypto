const path = require('path');
const DeclarationBundlerPlugin = require('declaration-bundler-webpack-plugin');
module.exports = {
  entry: {
    "sncrypto.js": "./lib/index",
    "sncrypto.min.js": "./lib/index"
  },
  resolve: {
    extensions: ['.ts', '.js'],
    alias: {
      "@Root": path.resolve(__dirname, "."),
      "@Lib": path.resolve(__dirname, "lib"),
      "@Crypto": path.resolve(__dirname, "lib/crypto")
    }
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
  plugins: [
    new DeclarationBundlerPlugin({
      moduleName: 'sncrypto',
      out: 'sncrypto.d.ts',
    })
  ],
  stats: {
    colors: true
  },
  devtool: 'source-map'
};
