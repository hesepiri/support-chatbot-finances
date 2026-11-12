/**
 * ChatWidget.jsx — Widget de chat de asistencia financiera en tiempo real.
 *
 * Demuestra:
 *   - WebSockets con Socket.IO (conexión, eventos, acknowledgements, reconexión).
 *   - React Hooks: useState (lo que se pinta), useRef (lo que persiste sin
 *     pintar) y useEffect (sincronización con el mundo exterior).
 *   - Cifrado E2E con Web Crypto API (ver shared/e2e.js para la explicación
 *     de cifrado asimétrico vs hashing).
 *
 * Flujo de seguridad:
 *   1. Al montar, el navegador genera SU par de llaves (pública/privada).
 *   2. Al conectar, intercambia llaves PÚBLICAS con el agente.
 *   3. Al enviar:  cifra con la llave PÚBLICA del agente  -> socket.
 *   4. Al recibir: descifra con SU llave PRIVADA          -> pantalla.
 */

import { useEffect, useRef, useState } from 'react';
import { io } from 'socket.io-client';
import {
  generateKeyPair,
  exportPublicKey,
  importPublicKey,
  encryptMessage,
  decryptMessage,
  fingerprint,
} from '../shared/e2e.js';
import './ChatWidget.css';

// En desarrollo el backend corre en :3001; en producción se sirve del mismo origen.
const SOCKET_URL =
  import.meta.env.VITE_SOCKET_URL || (import.meta.env.DEV ? 'http://localhost:3001' : undefined);

const MAX_MESSAGE_CHARS = 1000;

const STATUS_LABEL = {
  connecting: 'Conectando…',
  securing: 'Intercambiando llaves…',
  secure: 'En línea · cifrado E2E',
  offline: 'Sin conexión · reintentando…',
  error: 'No se pudo asegurar el canal',
};

const QUICK_REPLIES = [
  '¿Cómo armo un presupuesto?',
  'Quiero empezar a ahorrar',
  'Tengo deudas de tarjeta',
  '¿Cómo empiezo a invertir?',
];

const formatTime = (timestamp) =>
  new Date(timestamp).toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' });

export default function ChatWidget() {
  /* ---------- useState: datos que, al cambiar, deben re-renderizar ---------- */
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState('');
  const [status, setStatus] = useState('connecting');
  const [agentTyping, setAgentTyping] = useState(false);
  const [showWire, setShowWire] = useState(false); // "modo demo": ver el texto cifrado
  const [fingerprints, setFingerprints] = useState({ mine: null, agent: null });

  /* ---------- useRef: valores que persisten entre renders SIN provocar uno ---------- */
  const socketRef = useRef(null); // la conexión
  const myKeysRef = useRef(null); // { publicKey, privateKey } — la privada nunca va al estado ni al servidor
  const agentKeyRef = useRef(null); // llave pública del agente
  const bottomRef = useRef(null); // ancla del DOM para el auto-scroll
  const inputRef = useRef(null);

  /* ---------- useEffect #1: ciclo de vida de la conexión ----------
   * Dependencias [] => corre una vez al montar; la función que devuelve
   * (cleanup) corre al desmontar y cierra el socket. Esto reemplaza a
   * componentDidMount + componentWillUnmount de los componentes de clase.
   */
  useEffect(() => {
    let cancelled = false; // evita setState si el componente ya se desmontó
    const socket = io(SOCKET_URL, { autoConnect: false });
    socketRef.current = socket;

    // Se ejecuta en la primera conexión Y en cada reconexión: si el servidor
    // se reinicia, el agente tiene llaves nuevas y hay que volver a pedirlas.
    const exchangeKeys = async () => {
      setStatus('securing');
      try {
        const publicKey = await exportPublicKey(myKeysRef.current.publicKey);
        const response = await socket.timeout(5000).emitWithAck('key:exchange', { publicKey });
        if (!response?.ok) throw new Error(response?.error);

        const agentKey = await importPublicKey(response.publicKey);
        const agentFingerprint = await fingerprint(agentKey);
        if (cancelled) return;

        agentKeyRef.current = agentKey;
        setFingerprints((current) => ({ ...current, agent: agentFingerprint }));
        setStatus('secure');
      } catch {
        if (!cancelled) setStatus('error');
      }
    };

    const handleIncoming = async ({ id, from, sentAt, envelope }) => {
      try {
        // DESCIFRADO: solo nuestra llave PRIVADA puede abrir este sobre.
        const text = await decryptMessage(envelope, myKeysRef.current.privateKey);
        if (cancelled) return;
        setMessages((current) => [
          ...current,
          { id, from, text, sentAt, wire: envelope.ciphertext, state: 'delivered' },
        ]);
      } catch {
        // Sobre alterado o cifrado para otra llave: se descarta.
      }
    };

    const handleDisconnect = () => {
      agentKeyRef.current = null;
      setAgentTyping(false);
      setStatus('offline');
    };

    socket.on('connect', exchangeKeys);
    socket.on('disconnect', handleDisconnect);
    socket.on('connect_error', handleDisconnect);
    socket.on('chat:message', handleIncoming);
    socket.on('agent:typing', setAgentTyping);

    (async () => {
      try {
        // Paso 1: generar el par de llaves en ESTE navegador.
        const keys = await generateKeyPair();
        const myFingerprint = await fingerprint(keys.publicKey);
        if (cancelled) return;
        myKeysRef.current = keys;
        setFingerprints((current) => ({ ...current, mine: myFingerprint }));
        socket.connect(); // Paso 2: conectar (dispara `exchangeKeys`)
      } catch {
        // Web Crypto requiere contexto seguro (https o localhost).
        if (!cancelled) setStatus('error');
      }
    })();

    return () => {
      cancelled = true;
      socket.removeAllListeners();
      socket.disconnect();
    };
  }, []);

  /* ---------- useEffect #2: auto-scroll ----------
   * Depende de [messages, agentTyping]: después de cada render en el que
   * cambie alguno, baja al último mensaje.
   */
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, agentTyping]);

  const updateMessage = (id, patch) =>
    setMessages((current) => current.map((m) => (m.id === id ? { ...m, ...patch } : m)));

  const sendMessage = async (rawText) => {
    const text = rawText.trim();
    const socket = socketRef.current;
    if (!text || status !== 'secure' || !agentKeyRef.current) return;

    const id = crypto.randomUUID();
    // UI optimista: el mensaje aparece al instante como "enviando".
    setMessages((current) => [
      ...current,
      { id, from: 'user', text, sentAt: Date.now(), wire: null, state: 'sending' },
    ]);
    setDraft('');
    inputRef.current?.focus();

    try {
      // CIFRADO: con la llave PÚBLICA del agente. Ni siquiera nosotros
      // podríamos descifrar este sobre: no tenemos su llave privada.
      const envelope = await encryptMessage(text, agentKeyRef.current);
      updateMessage(id, { wire: envelope.ciphertext });

      // Acknowledgement de Socket.IO: el servidor confirma la recepción.
      const response = await socket.timeout(5000).emitWithAck('chat:message', { id, envelope });
      updateMessage(id, { state: response?.ok ? 'delivered' : 'failed' });
    } catch {
      updateMessage(id, { state: 'failed' });
    }
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    sendMessage(draft);
  };

  const isSecure = status === 'secure';

  return (
    <section className="chat" aria-label="Chat de asistencia financiera">
      <header className="chat__header">
        <div className="chat__avatar" aria-hidden="true">S</div>
        <div className="chat__identity">
          <h1>Sofía · Asistencia financiera</h1>
          <p className={`chat__status chat__status--${status}`}>
            <span className="chat__dot" aria-hidden="true" />
            {STATUS_LABEL[status]}
          </p>
        </div>
        <button
          type="button"
          className="chat__toggle"
          aria-pressed={showWire}
          onClick={() => setShowWire((value) => !value)}
          title="Muestra lo que realmente viaja por el socket"
        >
          {showWire ? 'Ocultar cifrado' : 'Ver cifrado'}
        </button>
      </header>

      {showWire && (
        <dl className="chat__keys">
          <div>
            <dt>Huella de tu llave pública (SHA-256)</dt>
            <dd>{fingerprints.mine ?? '—'}</dd>
          </div>
          <div>
            <dt>Huella de la llave del agente</dt>
            <dd>{fingerprints.agent ?? '—'}</dd>
          </div>
        </dl>
      )}

      <ol className="chat__messages" aria-live="polite">
        {messages.length === 0 && (
          <li className="chat__empty">
            <p>Pregunta lo que necesites sobre tus finanzas.</p>
            <div className="chat__quick">
              {QUICK_REPLIES.map((suggestion) => (
                <button
                  key={suggestion}
                  type="button"
                  disabled={!isSecure}
                  onClick={() => sendMessage(suggestion)}
                >
                  {suggestion}
                </button>
              ))}
            </div>
          </li>
        )}

        {messages.map((message) => (
          <li key={message.id} className={`bubble bubble--${message.from}`}>
            <p className="bubble__text">{message.text}</p>
            {showWire && message.wire && (
              <code className="bubble__wire" title="Texto cifrado que viajó por el socket">
                🔒 {message.wire.slice(0, 56)}…
              </code>
            )}
            <span className="bubble__meta">
              {formatTime(message.sentAt)}
              {message.from === 'user' && message.state === 'sending' && ' · enviando…'}
              {message.from === 'user' && message.state === 'delivered' && ' · entregado'}
              {message.state === 'failed' && (
                <>
                  {' · no enviado · '}
                  <button type="button" className="bubble__retry" onClick={() => sendMessage(message.text)}>
                    reintentar
                  </button>
                </>
              )}
            </span>
          </li>
        ))}

        {agentTyping && (
          <li className="bubble bubble--agent bubble--typing" aria-label="Sofía está escribiendo">
            <span /><span /><span />
          </li>
        )}
        <li ref={bottomRef} aria-hidden="true" />
      </ol>

      <form className="chat__form" onSubmit={handleSubmit}>
        <input
          ref={inputRef}
          type="text"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder={isSecure ? 'Escribe tu mensaje…' : 'Asegurando el canal…'}
          maxLength={MAX_MESSAGE_CHARS}
          disabled={!isSecure}
          aria-label="Mensaje"
          autoComplete="off"
        />
        <button type="submit" disabled={!isSecure || !draft.trim()}>
          Enviar
        </button>
      </form>

      <footer className="chat__footer">
        🔐 Cifrado de extremo a extremo · RSA-OAEP + AES-GCM (Web Crypto API)
      </footer>
    </section>
  );
}
