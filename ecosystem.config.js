module.exports = {
  apps : [{
    name: 'URL-Shortener',
    script: 'index.js',
    instances : 1,
    exec_mode : "cluster",
    env: {
        "NODE_ENV": "production"
    }
  }]
};
