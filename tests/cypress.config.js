const { defineConfig } = require('cypress')

module.exports = defineConfig({
  chromeWebSecurity: false,
  viewportWidth: 1920,
  viewportHeight: 1080,
  defaultCommandTimeout: 10000,
  videosFolder: 'cypress/reports/videos',
  screenshotsFolder: 'cypress/reports/screenshots',
  videoUploadOnPasses: false,
  retries: 1,
  reporter: 'mochawesome',
  reporterOptions: {
    reportDir: 'cypress/reports/separate-reports',
    overwrite: false,
    html: false,
    json: true,
  },
  e2e: {
    // We've imported your old cypress plugins here.
    // You may want to clean this up later by importing these.
    setupNodeEvents(on, config) {
      return require('./cypress/plugins/index.js')(on, config)
    },
    specPattern: 'cypress/e2e/**/*.spec.js',
  },
})
