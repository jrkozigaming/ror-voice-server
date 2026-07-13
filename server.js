const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');
const url = require('url');
const crypto = require('crypto');

// Cryptographic handshake secret key (keeps connections private and authentic)
const SECRET_KEY = 'RoRVoice_Auth_2026_Secure_Token!';

// Configure port (Render/Railway sets PORT env)
const PORT = process.env.PORT || 8080;

// Create HTTP server for health checks
const server = http.createServer((req, res) => {
    if (req.url === '/health' || req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('RoRVoice Server is running healthy!');
    } else {
        res.writeHead(404);
        res.end();
    }
});

// Create WebSocket server attached to the HTTP server
const wss = new WebSocketServer({ server });

const customRoomOwners = new Map(); // roomName -> ownerUser
const customRoomAllowed = new Map(); // roomName -> Set of allowedUsers

function validateHandshake(req) {
    try {
        const parsedUrl = url.parse(req.url, true);
        const t = parseInt(parsedUrl.query.t, 10);
        const h = parsedUrl.query.h;

        if (isNaN(t) || !h) {
            return false;
        }

        // Prevent replay attacks using a time window of +/- 3 minutes
        const currentMinutes = Math.floor(Date.now() / 1000 / 60);
        if (Math.abs(currentMinutes - t) > 3) {
            console.log(`[AUTH FAIL] Time skew / replay timeout. Client: ${t}, Server: ${currentMinutes}`);
            return false;
        }

        const raw = `${t}_${SECRET_KEY}`;
        const calculatedHash = crypto.createHash('sha256').update(raw).digest('hex');

        return calculatedHash === h;
    } catch (err) {
        console.error('Handshake validation error:', err);
        return false;
    }
}

wss.on('connection', (ws, req) => {
    if (!validateHandshake(req)) {
        console.log('Connection rejected: invalid or missing authentication handshake.');
        ws.close(4001, 'Unauthorized handshake');
        return;
    }

    console.log('New client connected and authenticated');
    ws.room = null;
    ws.user = null;
    ws.pendingRoom = null;

    ws.on('message', (message, isBinary) => {
        if (isBinary) {
            // Audio packet forwarding
            if (!ws.room || !ws.user) return;

            // Prepare the payload: [1 byte name length] [name bytes...] [raw opus audio bytes]
            const nameBuffer = Buffer.from(ws.user, 'utf8');
            const headerBuffer = Buffer.alloc(1 + nameBuffer.length);
            headerBuffer.writeUInt8(nameBuffer.length, 0);
            nameBuffer.copy(headerBuffer, 1);

            const broadcastPacket = Buffer.concat([headerBuffer, message]);

            // Forward to all OTHER clients in the same room
            wss.clients.forEach((client) => {
                if (client !== ws && client.room === ws.room && client.readyState === WebSocket.OPEN) {
                    client.send(broadcastPacket, { binary: true });
                }
            });
        } else {
            // Control/JSON messages
            try {
                const data = JSON.parse(message.toString());
                if (data.type === 'join') {
                    const oldRoom = ws.room;
                    const oldUser = ws.user;

                    // If already in a room, notify departure
                    if (oldRoom && oldUser) {
                        notifyRoomLeave(oldRoom, oldUser, ws);
                    }

                    ws.room = null;
                    ws.pendingRoom = null;
                    ws.user = data.user;

                    const roomName = data.room;

                    if (roomName.startsWith('custom_')) {
                        if (!customRoomOwners.has(roomName)) {
                            // First user creates and owns the custom room
                            customRoomOwners.set(roomName, data.user);
                            if (!customRoomAllowed.has(roomName)) {
                                customRoomAllowed.set(roomName, new Set());
                            }
                            customRoomAllowed.get(roomName).add(data.user);

                            ws.room = roomName;
                            console.log(`User ${ws.user} created and joined room ${ws.room} as owner`);
                            ws.send(JSON.stringify({ type: 'joined', room: ws.room, isOwner: true }));
                            broadcastToRoom(ws.room, { type: 'user_joined', user: ws.user }, ws);
                        } else {
                            // Room exists, check permission
                            const allowed = customRoomAllowed.get(roomName);
                            if (allowed && allowed.has(data.user)) {
                                ws.room = roomName;
                                console.log(`User ${ws.user} joined room ${ws.room}`);
                                ws.send(JSON.stringify({ type: 'joined', room: ws.room }));
                                broadcastToRoom(ws.room, { type: 'user_joined', user: ws.user }, ws);
                            } else {
                                // Place in pending state
                                ws.pendingRoom = roomName;
                                console.log(`User ${ws.user} wants to join room ${roomName}. Waiting for owner.`);
                                ws.send(JSON.stringify({ type: 'join_pending', room: roomName }));

                                // Notify owner
                                const ownerName = customRoomOwners.get(roomName);
                                let ownerFound = false;
                                wss.clients.forEach((client) => {
                                    if (client.user === ownerName && client.room === roomName && client.readyState === WebSocket.OPEN) {
                                        client.send(JSON.stringify({ type: 'join_request', room: roomName, user: data.user }));
                                        ownerFound = true;
                                    }
                                });

                                // If owner is offline, auto-promote this user to owner
                                if (!ownerFound) {
                                    console.log(`Owner ${ownerName} not found in room. Transferring ownership to ${data.user}.`);
                                    customRoomOwners.set(roomName, data.user);
                                    customRoomAllowed.get(roomName).add(data.user);
                                    ws.room = roomName;
                                    ws.pendingRoom = null;
                                    ws.send(JSON.stringify({ type: 'joined', room: ws.room, isOwner: true }));
                                    broadcastToRoom(ws.room, { type: 'user_joined', user: ws.user }, ws);
                                }
                            }
                        }
                    } else {
                        // Standard room
                        ws.room = roomName;
                        console.log(`User ${ws.user} joined room ${ws.room}`);
                        ws.send(JSON.stringify({ type: 'joined', room: ws.room }));
                        broadcastToRoom(ws.room, { type: 'user_joined', user: ws.user }, ws);
                    }
                } else if (data.type === 'allow') {
                    const roomName = ws.room;
                    if (roomName && roomName.startsWith('custom_')) {
                        const ownerName = customRoomOwners.get(roomName);
                        if (ws.user === ownerName) {
                            const targetUser = data.target;
                            if (!customRoomAllowed.has(roomName)) {
                                customRoomAllowed.set(roomName, new Set());
                            }
                            customRoomAllowed.get(roomName).add(targetUser);
                            console.log(`Owner ${ws.user} allowed ${targetUser} to join ${roomName}`);

                            wss.clients.forEach((client) => {
                                if (client.user === targetUser && client.pendingRoom === roomName && client.readyState === WebSocket.OPEN) {
                                    client.room = roomName;
                                    client.pendingRoom = null;
                                    client.send(JSON.stringify({ type: 'joined', room: roomName }));
                                    broadcastToRoom(roomName, { type: 'user_joined', user: targetUser }, client);
                                }
                            });
                        }
                    }
                } else if (data.type === 'deny') {
                    const roomName = ws.room;
                    if (roomName && roomName.startsWith('custom_')) {
                        const ownerName = customRoomOwners.get(roomName);
                        if (ws.user === ownerName) {
                            const targetUser = data.target;
                            console.log(`Owner ${ws.user} denied ${targetUser} from joining ${roomName}`);

                            wss.clients.forEach((client) => {
                                if (client.user === targetUser && client.pendingRoom === roomName && client.readyState === WebSocket.OPEN) {
                                    client.pendingRoom = null;
                                    client.send(JSON.stringify({ type: 'join_denied', room: roomName }));
                                }
                            });
                        }
                    }
                } else if (data.type === 'kick') {
                    const roomName = ws.room;
                    if (roomName) {
                        let canKick = false;
                        if (roomName.startsWith('custom_')) {
                            const ownerName = customRoomOwners.get(roomName);
                            if (ws.user === ownerName) {
                                canKick = true;
                                if (customRoomAllowed.has(roomName)) {
                                    customRoomAllowed.get(roomName).delete(data.target);
                                }
                            }
                        } else {
                            const leaderPart = roomName.substring(roomName.indexOf('_') + 1);
                            if (ws.user.toLowerCase() === leaderPart.toLowerCase()) {
                                canKick = true;
                            }
                        }

                        if (canKick) {
                            const targetUser = data.target;
                            console.log(`Leader/Owner ${ws.user} kicked ${targetUser} from ${roomName}`);
                            wss.clients.forEach((client) => {
                                if (client.user === targetUser && client.room === roomName && client.readyState === WebSocket.OPEN) {
                                    client.room = null;
                                    client.send(JSON.stringify({ type: 'kicked', room: roomName }));
                                    notifyRoomLeave(roomName, targetUser, client);
                                }
                            });
                        }
                    }
                } else if (data.type === 'mute') {
                    if (ws.room && ws.user) {
                        broadcastToRoom(ws.room, { type: 'user_muted', user: ws.user, muted: data.muted }, ws);
                    }
                } else if (data.type === 'permission') {
                    if (ws.room && ws.user) {
                        broadcastToRoom(ws.room, { type: 'permission_update', target: data.target, allow: data.allow });
                    }
                }
            } catch (err) {
                console.error('Failed to parse control message:', err);
            }
        }
    });

    ws.on('close', () => {
        console.log(`Client disconnected: ${ws.user || 'unnamed'}`);
        if (ws.room && ws.user) {
            notifyRoomLeave(ws.room, ws.user, ws);
        }
    });
});

function notifyRoomLeave(room, user, excludeWs) {
    console.log(`User ${user} left room ${room}`);
    broadcastToRoom(room, { type: 'user_left', user }, excludeWs);

    if (room.startsWith('custom_') && customRoomOwners.get(room) === user) {
        let newOwnerWs = null;
        wss.clients.forEach((client) => {
            if (client !== excludeWs && client.room === room && client.readyState === WebSocket.OPEN) {
                newOwnerWs = client;
            }
        });
        if (newOwnerWs) {
            customRoomOwners.set(room, newOwnerWs.user);
            if (!customRoomAllowed.has(room)) {
                customRoomAllowed.set(room, new Set());
            }
            customRoomAllowed.get(room).add(newOwnerWs.user);
            newOwnerWs.send(JSON.stringify({ type: 'owner_changed', isOwner: true }));
            console.log(`Owner of ${room} changed to ${newOwnerWs.user}`);
        } else {
            customRoomOwners.delete(room);
            customRoomAllowed.delete(room);
            console.log(`Room ${room} is now empty. Cleaned up.`);
        }
    }
}

function broadcastToRoom(room, messageObj, excludeWs) {
    const payload = JSON.stringify(messageObj);
    wss.clients.forEach((client) => {
        if (client !== excludeWs && client.room === room && client.readyState === WebSocket.OPEN) {
            client.send(payload, { binary: false });
        }
    });
}

// Start the server
server.listen(PORT, () => {
    console.log(`RoRVoice server listening on port ${PORT}`);
});
