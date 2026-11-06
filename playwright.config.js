const {defineConfig, devices} = require('@playwright/test');
module.exports = defineConfig({
  testDir:'tests', testMatch:'ui.spec.js', timeout:45000, workers:1, reporter:'list',
  use:{baseURL:'http://127.0.0.1:5558',headless:true,
    launchOptions:process.env.SKVM_BROWSER_EXECUTABLE_PATH?{executablePath:process.env.SKVM_BROWSER_EXECUTABLE_PATH,args:['--no-sandbox','--disable-dev-shm-usage']}:{}},
  projects:[{name:'desktop',use:{viewport:{width:1440,height:960}}},{name:'android',use:{...devices['Pixel 7']}}],
  webServer:{command:'.venv/bin/python tests/ui_server.py',url:'http://127.0.0.1:5558',reuseExistingServer:false,timeout:30000}
});
