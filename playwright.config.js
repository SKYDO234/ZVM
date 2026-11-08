const {defineConfig, devices} = require('@playwright/test');
module.exports = defineConfig({
  testDir:'tests', testMatch:['ui.spec.js','ui-sshx.spec.js','ui-lifecycle.spec.js','ui-recovery.spec.js'], timeout:45000, workers:1, reporter:'list',
  use:{baseURL:'http://127.0.0.1:5558',headless:true,
    launchOptions:process.env.SKVM_BROWSER_EXECUTABLE_PATH?{executablePath:process.env.SKVM_BROWSER_EXECUTABLE_PATH,args:['--no-sandbox','--disable-dev-shm-usage']}:{}},
  projects:[
    {name:'desktop',testMatch:'ui.spec.js',use:{viewport:{width:1440,height:960}}},
    {name:'android',testMatch:'ui.spec.js',use:{...devices['Pixel 7']}},
    {name:'sshx-desktop',testMatch:['ui-sshx.spec.js','ui-lifecycle.spec.js','ui-recovery.spec.js'],use:{baseURL:'http://127.0.0.1:5559',viewport:{width:1440,height:960}}},
    {name:'sshx-android',testMatch:['ui-sshx.spec.js','ui-lifecycle.spec.js','ui-recovery.spec.js'],use:{...devices['Pixel 7'],baseURL:'http://127.0.0.1:5559'}}
  ],
  webServer:[
    {command:'.venv/bin/python tests/ui_server.py',url:'http://127.0.0.1:5558',reuseExistingServer:false,timeout:30000},
    {command:'.venv/bin/python tests/sshx_ui_server.py',url:'http://127.0.0.1:5559',reuseExistingServer:false,timeout:30000}
  ]
});
