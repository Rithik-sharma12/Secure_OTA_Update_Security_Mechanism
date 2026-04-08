// Node.js UDP listener inside the IDE (TypeScript)
import * as dgram from 'dgram';

const socket = dgram.createSocket('udp4');

socket.bind(5007, () => {
    socket.setBroadcast(true);
});

socket.on('message', (msg, rinfo) => {
    const device = JSON.parse(msg.toString());
    // device = { mac, version, sketch, board, ip, status }
    
    // Update Live Device Panel with this device's info
    updateDevicePanel(device);
    
    // Record last-seen timestamp
    deviceRegistry[device.mac] = {
        ...device,
        lastSeen: Date.now()
    };
});