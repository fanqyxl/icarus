
const net = require('net')
const https = require('https')
const proc = require('process')
const fs= require('fs');
/**
 * @param {import('./proxy').ServerConfig} config
 * @param {net.Socket} socket 
 */
function expressHandlerFromSocket(config, socket) {

}
class MiniServer {
    static pInitial = 3001;
    internalServer;
    expressApp;
    port;
    constructor(hand,cert,key, port = MiniServer.pInitial++) {
        // console.log(hand.toString());
        // console.debug("miniserver creating")
        // console.log(port)
        this.internalServer = https.createServer({
            cert: fs.readFileSync(cert),
            key: fs.readFileSync(key, 'utf-8'),
            passphrase: 'icarus',
        }, hand);
        this.internalServer.listen(port, () => {
        	// console.debug(`MiniServer is running on port ${port}`);
        });
        this.port = port;
    }
}
function getMiniServer(hand, cert, key) {
    
    return new MiniServer(hand, cert, key);
}
module.exports = {
    getMiniServer
}