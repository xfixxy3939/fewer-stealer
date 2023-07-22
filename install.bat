echo off
::color 02

call npm i
call node crypter.js
call npm run electron-builder --win
::call npm start