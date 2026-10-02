'use strict';

// Startup file for cPanel "Setup Node.js App" (LiteSpeed lsnode / Passenger)
// and for `npm start`. start() reports its own errors and sets the exit code.
require('./src/server').start();
