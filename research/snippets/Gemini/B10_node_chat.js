const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Temporary in-memory storage (Swap with MongoDB or PostgreSQL for persistence)
let messageHistory = [];

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Socket.io Logic
io.on('connection', (socket) => {
  console.log('A user connected');

  // Send existing messages to the newly connected user
  socket.emit('load history', messageHistory);

  socket.on('chat message', (data) => {
    const msgData = {
      user: data.user || 'Anonymous',
      text: data.text,
      time: new Date().toLocaleTimeString()
    };

    messageHistory.push(msgData); // Store it
    io.emit('chat message', msgData); // Broadcast it to everyone
  });

  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

server.listen(3000, () => {
  console.log('Chat server running on http://localhost:3000');
});