const {randomBytes} = require('crypto')

const serialNumber = randomBytes(20).toString('hex')

// if the serial number starts with a 1, then it wll be considered negative. So, prefix with 00
console.log('00' + serialNumber)
