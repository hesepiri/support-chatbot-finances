/**
 * Prueba de humo de extremo a extremo: `npm test`
 * Levanta el servidor, se conecta como un usuario real, intercambia llaves,
 * envía un mensaje cifrado y verifica que la respuesta del agente se descifra.
 */
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { io } from 'socket.io-client';
import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  encryptMessage,
  decryptMessage,
} from '../shared/e2e.js';

const PORT = 3099;
const server = spawn(process.execPath, ['server.js'], {
  env: { ...process.env, PORT: String(PORT) },
  stdio: ['ignore', 'pipe', 'inherit'],
});

try {
  await new Promise((resolve, reject) => {
    server.stdout.on('data', (chunk) => chunk.toString().includes('Servidor de chat') && resolve());
    server.on('exit', () => reject(new Error('El servidor terminó antes de arrancar')));
  });

  const socket = io(`http://localhost:${PORT}`);
  const keys = await generateKeyPair();

  // 1. Sin intercambio de llaves, el servidor rechaza mensajes.
  const rejected = await socket.timeout(5000).emitWithAck('chat:message', { envelope: {} });
  assert.equal(rejected.ok, false);

  // 2. Intercambio de llaves públicas.
  const exchange = await socket
    .timeout(5000)
    .emitWithAck('key:exchange', { publicKey: await exportPublicKey(keys.publicKey) });
  assert.equal(exchange.ok, true);
  const agentKey = await importPublicKey(exchange.publicKey);

  // 3. Mensaje cifrado -> respuesta cifrada.
  const reply = new Promise((resolve) => socket.once('chat:message', resolve));
  const envelope = await encryptMessage('Hola, ¿cómo armo un presupuesto? 💸', agentKey);
  assert.ok(!JSON.stringify(envelope).includes('presupuesto'), 'el texto plano no debe viajar');

  const ack = await socket.timeout(5000).emitWithAck('chat:message', { id: '1', envelope });
  assert.equal(ack.ok, true);

  const incoming = await reply;
  const text = await decryptMessage(incoming.envelope, keys.privateKey);
  assert.match(text, /Sofía/);

  // 4. Una llave privada distinta NO puede descifrar la respuesta.
  const stranger = await generateKeyPair();
  await assert.rejects(decryptMessage(incoming.envelope, stranger.privateKey));

  socket.disconnect();
  console.log('✔ Prueba de humo superada: intercambio de llaves, cifrado y descifrado correctos.');
} finally {
  server.kill();
}
