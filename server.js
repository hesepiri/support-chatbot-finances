/**
 * server.js — Backend del Módulo de Chat de Asistencia Financiera.
 *
 * Stack: Node.js + Express + Socket.IO.
 *
 * Este archivo tiene dos responsabilidades, separadas a propósito:
 *
 *   1. CAPA DE TRANSPORTE (Express + Socket.IO)
 *      Gestiona conexiones, recibe eventos y emite respuestas. Solo ve
 *      "sobres" cifrados: { wrappedKey, iv, ciphertext }.
 *
 *   2. AGENTE SIMULADO (el otro "extremo" de la conversación)
 *      Tiene su propio par de llaves. Descifra lo que le escribe el usuario
 *      y cifra su respuesta con la llave pública del usuario.
 *
 * NOTA DE HONESTIDAD PARA LA DEMO: en un sistema E2E real, el agente sería
 * otro cliente (otra app, otro dispositivo) y el servidor sería un simple
 * mensajero incapaz de leer nada. Aquí el agente vive en el mismo proceso
 * por simplicidad, pero el código de transporte nunca toca texto plano:
 * mover el agente a otro cliente no cambiaría ni una línea del protocolo.
 */

import { createServer } from 'node:http';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { Server } from 'socket.io';
import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  encryptMessage,
  decryptMessage,
  fingerprint,
  isEnvelope,
} from './shared/e2e.js';

const PORT = process.env.PORT || 3001;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
const MAX_MESSAGE_CHARS = 1000;

/* ======================================================================
 * 2. AGENTE SIMULADO
 * ====================================================================== */

// El agente genera su par de llaves una vez, al arrancar.
// La privada nunca sale de aquí; la pública se entrega a cada usuario.
const agentKeys = await generateKeyPair();
const agentPublicJwk = await exportPublicKey(agentKeys.publicKey);
const agentFingerprint = await fingerprint(agentKeys.publicKey);

const AGENT_RULES = [
  {
    match: /\b(hola|buenas|buenos d[ií]as|qu[eé] tal)\b/i,
    reply: '¡Hola! Soy Sofía, tu asistente financiera. Puedo orientarte sobre presupuesto, ahorro, deudas o inversión. ¿Por dónde empezamos?',
  },
  {
    match: /presupuesto|gastos?|gastar/i,
    reply: 'Un buen punto de partida es la regla 50/30/20: 50% a necesidades, 30% a gustos y 20% a ahorro o pago de deudas. ¿Quieres que la apliquemos a tu ingreso mensual?',
  },
  {
    match: /ahorr|fondo de emergencia|guardar/i,
    reply: 'Lo primero es un fondo de emergencia de 3 a 6 meses de gastos fijos. Automatiza una transferencia el día que recibes tu ingreso: así ahorras antes de gastar.',
  },
  {
    match: /deuda|tarjeta|cr[eé]dito|intereses|pr[eé]stamo/i,
    reply: 'Para deudas hay dos métodos: "avalancha" (pagar primero la de mayor interés, ahorras más dinero) y "bola de nieve" (primero la más pequeña, ganas motivación). ¿Cuál se ajusta más a ti?',
  },
  {
    match: /inver|cetes|fondos?|acciones|rendimiento/i,
    reply: 'Antes de invertir conviene tener tu fondo de emergencia y no tener deudas caras. Después, define plazo y tolerancia al riesgo. Esto es orientación general, no asesoría de inversión personalizada.',
  },
  {
    match: /segur|cifrad|privacidad|encript/i,
    reply: 'Esta conversación viaja cifrada de extremo a extremo: tu navegador cifra cada mensaje con mi llave pública y solo mi llave privada puede abrirlo. 🔐',
  },
  {
    match: /gracias|adi[oó]s|hasta luego/i,
    reply: '¡Con gusto! Recuerda que la constancia vale más que la cantidad. Aquí estaré cuando me necesites.',
  },
];

const AGENT_FALLBACK =
  'Entiendo. Puedo ayudarte con presupuesto, ahorro, deudas o inversión. ¿Sobre cuál de esos temas quieres profundizar?';

function composeAgentReply(userText) {
  const rule = AGENT_RULES.find(({ match }) => match.test(userText));
  return rule ? rule.reply : AGENT_FALLBACK;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* ======================================================================
 * 1. CAPA DE TRANSPORTE
 * ====================================================================== */

const app = express();
const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: { origin: CLIENT_ORIGIN },
  maxHttpBufferSize: 32 * 1024, // un chat de texto no necesita más de 32 KB por evento
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', connectedUsers: io.engine.clientsCount });
});

// En producción (`npm run build && npm start`) el mismo servidor entrega el frontend.
const distDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'dist');
if (existsSync(distDir)) app.use(express.static(distDir));

io.on('connection', (socket) => {
  console.log(`[socket] conectado     ${socket.id} (usuarios: ${io.engine.clientsCount})`);

  /**
   * Intercambio de llaves PÚBLICAS.
   * El usuario envía la suya y recibe la del agente en el acknowledgement.
   * Las privadas nunca viajan: ese es todo el punto del cifrado asimétrico.
   */
  socket.on('key:exchange', async (payload, ack) => {
    if (typeof ack !== 'function') return;
    try {
      socket.data.userPublicKey = await importPublicKey(payload?.publicKey);
      const userFingerprint = await fingerprint(socket.data.userPublicKey);
      console.log(`[socket] llaves        ${socket.id} huella usuario ${userFingerprint}`);
      ack({ ok: true, publicKey: agentPublicJwk });
    } catch {
      ack({ ok: false, error: 'Llave pública inválida.' });
    }
  });

  /**
   * Mensaje del usuario. `payload.envelope` llega cifrado con la llave
   * pública del agente.
   */
  socket.on('chat:message', async (payload, ack) => {
    const respond = typeof ack === 'function' ? ack : () => {};

    if (!socket.data.userPublicKey) {
      return respond({ ok: false, error: 'Primero hay que intercambiar llaves.' });
    }
    if (!isEnvelope(payload?.envelope)) {
      return respond({ ok: false, error: 'Formato de mensaje inválido.' });
    }

    // Esto es TODO lo que ve la capa de transporte (y cualquiera que espíe la red):
    console.log(`[socket] mensaje       ${socket.id} ${payload.envelope.ciphertext.slice(0, 32)}…`);

    let userText;
    try {
      // --- a partir de aquí actúa el AGENTE, con su llave PRIVADA ---
      userText = await decryptMessage(payload.envelope, agentKeys.privateKey);
    } catch {
      return respond({ ok: false, error: 'No se pudo descifrar el mensaje.' });
    }
    if (userText.length > MAX_MESSAGE_CHARS) {
      return respond({ ok: false, error: 'Mensaje demasiado largo.' });
    }

    respond({ ok: true }); // acuse de recibo -> el cliente marca "entregado"

    try {
      socket.emit('agent:typing', true);
      const replyText = composeAgentReply(userText);
      await sleep(600 + Math.min(replyText.length * 12, 1600)); // "escribiendo…"

      // El agente cifra con la llave PÚBLICA del usuario: solo ese navegador,
      // que guarda la privada, podrá leer la respuesta.
      const envelope = await encryptMessage(replyText, socket.data.userPublicKey);
      socket.emit('chat:message', {
        id: crypto.randomUUID(),
        from: 'agent',
        sentAt: Date.now(),
        envelope,
      });
    } catch (error) {
      console.error(`[agente] error respondiendo a ${socket.id}:`, error.message);
    } finally {
      socket.emit('agent:typing', false);
    }
  });

  socket.on('disconnect', (reason) => {
    console.log(`[socket] desconectado  ${socket.id} (${reason})`);
  });
});

httpServer.listen(PORT, () => {
  console.log(`Servidor de chat en http://localhost:${PORT}`);
  console.log(`Huella de la llave pública del agente: ${agentFingerprint}`);
});
