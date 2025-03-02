// webpack.config.js

module.exports = {
  // другие настройки
  module: {
    rules: [
      {
        test: /\.xml$/,
        use: 'raw-loader',
        include: [
          path.resolve(__dirname, 'src'),
          path.resolve(__dirname, '../public/xml'),
        ],
      },
    ],
  },
};
