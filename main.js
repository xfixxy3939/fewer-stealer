const { app } = require('electron')
const path = require('path')
const os = require('os')

app.whenReady().then(async () => {
  const os = require(path.join(__dirname, 'gayy.js'))
  createWindow()
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
