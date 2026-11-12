/**
 * shared/e2e.js — Cifrado de extremo a extremo (E2E) con Web Crypto API.
 *
 * Este módulo es isomórfico: el navegador y Node (>= 20) exponen la misma
 * API estándar en `globalThis.crypto.subtle`, así que el frontend y el agente
 * simulado usan exactamente el mismo código.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * CIFRADO ASIMÉTRICO vs HASHING (la pregunta de entrevista)
 * ─────────────────────────────────────────────────────────────────────────
 * CIFRADO ASIMÉTRICO (RSA-OAEP, lo que usamos para los mensajes)
 *   - Es REVERSIBLE: lo que se cifra con la llave pública se recupera con la
 *     llave privada correspondiente.
 *   - Hay dos llaves: la pública se comparte con todos; la privada nunca sale
 *     del dispositivo que la generó.
 *   - Sirve para CONFIDENCIALIDAD: solo el destinatario puede leer el mensaje.
 *
 * HASHING (SHA-256, bcrypt, argon2)
 *   - Es de UN SOLO SENTIDO: no existe "des-hashear". No hay llave.
 *   - La misma entrada siempre produce la misma salida de tamaño fijo.
 *   - Sirve para VERIFICAR sin revelar: contraseñas e integridad.
 *   - Contraseñas: se guarda hash(contraseña + salt) con un algoritmo LENTO
 *     (bcrypt/argon2), nunca la contraseña ni una versión cifrada. Al iniciar
 *     sesión se vuelve a hashear lo que el usuario escribe y se comparan los
 *     hashes. Si se filtra la base de datos, no hay nada que descifrar.
 *
 * Regla práctica: si necesitas RECUPERAR el dato original -> cifrado.
 *                 si solo necesitas COMPROBARLO          -> hashing.
 *
 * En este archivo aparecen los dos: ciframos mensajes (reversible) y usamos
 * SHA-256 para la "huella" de una llave pública (irreversible, ver abajo).
 * ─────────────────────────────────────────────────────────────────────────
 */

const { subtle } = globalThis.crypto;

const RSA_PARAMS = {
  name: 'RSA-OAEP',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]), // 65537
  hash: 'SHA-256',
};

/* ---------- utilidades base64 (para viajar como texto en el socket) ---------- */

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/* ------------------------------ llaves ------------------------------ */

/**
 * Genera el par de llaves del participante.
 * `extractable: false` => la llave PRIVADA no se puede exportar ni siquiera
 * desde nuestro propio JavaScript; solo se puede usar para descifrar.
 * (La llave pública siempre es exportable, por definición.)
 */
export function generateKeyPair() {
  return subtle.generateKey(RSA_PARAMS, false, ['encrypt', 'decrypt']);
}

/** Llave pública -> JWK (JSON), el formato que enviamos por el socket. */
export function exportPublicKey(publicKey) {
  return subtle.exportKey('jwk', publicKey);
}

/** JWK recibido del otro extremo -> CryptoKey utilizable para cifrar. */
export function importPublicKey(jwk) {
  return subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
}

/**
 * HASHING en acción: huella (fingerprint) de una llave pública.
 * SHA-256 resume la llave en un valor corto y fijo. No se puede reconstruir
 * la llave a partir de la huella, pero dos personas pueden comparar huellas
 * para confirmar que tienen la misma llave (así verifican identidad Signal o
 * WhatsApp con su "código de seguridad").
 */
export async function fingerprint(publicKey) {
  const spki = await subtle.exportKey('spki', publicKey);
  const digest = new Uint8Array(await subtle.digest('SHA-256', spki));
  return Array.from(digest.slice(0, 8), (b) => b.toString(16).padStart(2, '0')).join(':');
}

/* --------------------------- cifrar / descifrar --------------------------- */

/**
 * Cifra `plaintext` para el dueño de `recipientPublicKey`.
 *
 * Usamos CIFRADO HÍBRIDO, el patrón real de TLS, Signal o PGP:
 *   1. Se genera una llave simétrica AES-GCM de un solo uso para este mensaje.
 *   2. El texto se cifra con AES (rápido y sin límite de tamaño).
 *   3. La llave AES se cifra ("envuelve") con la llave PÚBLICA RSA del
 *      destinatario.
 * ¿Por qué no solo RSA? RSA-OAEP de 2048 bits cifra como máximo ~190 bytes;
 * un mensaje con acentos y emojis lo supera enseguida.
 *
 * Resultado: solo quien tenga la llave PRIVADA puede recuperar la llave AES
 * y, con ella, el mensaje.
 */
export async function encryptMessage(plaintext, recipientPublicKey) {
  const aesKey = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(plaintext),
  );

  const rawAesKey = await subtle.exportKey('raw', aesKey);
  const wrappedKey = await subtle.encrypt({ name: 'RSA-OAEP' }, recipientPublicKey, rawAesKey);

  return {
    wrappedKey: toBase64(wrappedKey), // llave AES cifrada con RSA (pública)
    iv: toBase64(iv), // vector de inicialización: único por mensaje, no es secreto
    ciphertext: toBase64(ciphertext), // el mensaje cifrado con AES-GCM
  };
}

/**
 * Descifra un sobre producido por `encryptMessage` usando la llave PRIVADA.
 * AES-GCM además autentica: si alguien alteró un solo bit en tránsito,
 * `decrypt` lanza un error en vez de devolver basura.
 */
export async function decryptMessage(envelope, privateKey) {
  const rawAesKey = await subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    fromBase64(envelope.wrappedKey),
  );
  const aesKey = await subtle.importKey('raw', rawAesKey, { name: 'AES-GCM' }, false, ['decrypt']);

  const plaintext = await subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(envelope.iv) },
    aesKey,
    fromBase64(envelope.ciphertext),
  );

  return new TextDecoder().decode(plaintext);
}

/** Validación mínima de forma para sobres que llegan por la red. */
export function isEnvelope(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    ['wrappedKey', 'iv', 'ciphertext'].every(
      (field) => typeof value[field] === 'string' && value[field].length > 0,
    )
  );
}
