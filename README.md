# 1. INFORMACION GENERAL ℹ️

- Nombre del proyecto: FinChat: Módulo de Asistencia Financiera en Tiempo Real con Cifrado E2E
- Especialidad (DS/DA/Web/QA/UX-UI): Web (Full Stack)
- Fuente del proyecto: Brief técnico derivado del feedback de simulación de entrevista (TripleTen).
- Link a la fuente original (dataset, repo, app a testear, brief): N/A (Entrevista de simulación)
- Link al proyecto publicado: [Repo en GitHub](https://github.com/hesepiri/support-chatbot-finances)

# 2. OBJETIVO 🎯

Desarrollar una prueba de concepto de un chat en tiempo real para una futura aplicación de finanzas personales. Resuelve la necesidad de comunicación instantánea y segura entre el usuario y el sistema, implementando cifrado de extremo a extremo (E2E) y demostrando la diferencia práctica entre cifrado asimétrico y hashing.

# 3. PLAN DE TRABAJO (3 a 5 pasos) ✍️

1. Exploracion inicial
   Investigación sobre la integración de Socket.IO en Node.js y React, y comprensión teórica de la Web Crypto API para la manipulación de llaves criptográficas en el navegador.
2. Preparacion
   Configuración del entorno de desarrollo (Node.js/Express para backend, Vite/React para frontend) y definición de la arquitectura cliente-servidor para el manejo de los eventos del socket y el almacenamiento seguro de llaves en memoria.
3. Construccion
   Desarrollo del servidor de sockets como capa de transporte de "sobres" cifrados. Creación del componente `ChatWidget.jsx` integrando React Hooks (`useState` para reactividad, `useRef` para aislar llaves y conexiones, `useEffect` para el ciclo de vida). Implementación de cifrado híbrido (AES-GCM envuelto en RSA-OAEP).
4. Evaluacion
   Ejecución de pruebas de humo automatizadas (`smoke.test.js`) para validar el intercambio de llaves y el flujo de cifrado/descifrado. Pruebas manuales en el navegador verificando el auto-scroll, la latencia y la actualización de UI optimista (enviando/entregado).
5. Conclusiones y proximos pasos
   Redacción de la documentación técnica y preparación del discurso para la defensa técnica (explicación del flujo de Hooks: estado -> render -> efecto; y Cifrado vs Hashing).

# 4. PREGUNTAS CLAVE ❓

- ¿Cuáles son los límites de seguridad de esta prueba de concepto? (Ej. El agente simulado vive en el mismo proceso que el transporte; las llaves solo viven en memoria y se pierden al recargar la página).
- ¿Qué pasaría si este sistema escala a un entorno real de producción? (Se requeriría separar al agente en un cliente independiente y utilizar adaptadores como Redis para manejar múltiples instancias de Socket.IO).

# 5. QUE SE HIZO Y COMO 📲

Se construyó una arquitectura Full Stack separando responsabilidades: `server.js` como transporte, y `ChatWidget.jsx` (React) para la interfaz.
Se hizo un uso intensivo de **React Hooks**: `useEffect` para conectar/desconectar los listeners del socket al montar/desmontar el componente (evitando fugas de memoria); `useRef` para mantener viva la conexión y guardar la llave privada sin provocar re-renders; y `useState` para el historial de la conversación.
En seguridad, se superó el límite de tamaño de datos del cifrado asimétrico tradicional implementando **Cifrado Híbrido**: el mensaje se cifra con AES-GCM (simétrico, sin límite de tamaño), y la llave AES se envuelve con RSA-OAEP (asimétrico). Además, se utilizó SHA-256 (hashing) para generar huellas digitales comprobables de las llaves públicas.

# 6. RESULTADOS 🙂

Se logró un chat funcional bidireccional con una interfaz de UI optimista que retroalimenta al usuario en tiempo real. El sistema aprueba las pruebas de humo locales y valida correctamente que la capa de transporte no pueda leer el contenido de los mensajes sin la llave privada correspondiente, cumpliendo el requisito de extremo a extremo simulado.

# 7. CONCLUSIONES 📋

El proyecto consolidó mi comprensión profunda de React Hooks, dejando claro el orden de ejecución real: estado -> render -> efecto. Aprendí a separar la lógica visual de las dependencias externas (conexiones). En el ámbito de seguridad, logré interiorizar la diferencia clave: el cifrado se usa para recuperar datos originales, mientras que el hashing es unidireccional y se usa solo para verificación. Con más tiempo, aislaría la lógica del agente y persistiría el historial del chat en una base de datos.

# 8. DOCUMENTACION 📖

# Chat de Asistencia Financiera en Tiempo Real

Módulo de chat de soporte para una futura app de finanzas personales. El usuario conversa con un agente simulado ("Sofía") y cada mensaje viaja cifrado de extremo a extremo.

**Stack:** Node.js · Express · Socket.IO · React (Hooks) · Web Crypto API · Vite

## Qué demuestra

| Concepto                                                                  | Dónde verlo                       |
| ------------------------------------------------------------------------- | --------------------------------- |
| WebSockets con Socket.IO: conexión, eventos, acknowledgements, reconexión | `server.js`, `src/ChatWidget.jsx` |
| React Hooks: `useState`, `useEffect`, `useRef`                            | `src/ChatWidget.jsx`              |
| Cifrado asimétrico (RSA-OAEP) + híbrido con AES-GCM                       | `shared/e2e.js`                   |
| Hashing (SHA-256) y su diferencia con el cifrado                          | `shared/e2e.js` (`fingerprint`)   |

## Cómo ejecutarlo

Requiere Node.js 20 o superior.

```bash
npm install
npm run dev      # backend en :3001 + frontend en http://localhost:5173
npm test         # prueba de humo E2E (servidor + cliente + cifrado)
```

Modo producción en un solo puerto: `npm run build && npm start` y abre http://localhost:3001.

En el widget, el botón **Ver cifrado** muestra las huellas de las llaves y el texto cifrado que realmente viajó por el socket en cada mensaje.

## Flujo de seguridad

```
Navegador (usuario)                    Servidor                     Agente simulado
───────────────────                    ────────                     ───────────────
genera par de llaves                                                genera par de llaves
        │── key:exchange { pública usuario } ─────────────────────────────▶│
        │◀──────────────────────────── ack { pública agente } ─────────────│
cifra con PÚBLICA del agente
        │── chat:message { wrappedKey, iv, ciphertext } ──────────────────▶│
        │                                                  descifra con SU PRIVADA
        │                                                  cifra con PÚBLICA del usuario
        │◀──────────────── chat:message { wrappedKey, iv, ciphertext } ────│
descifra con SU PRIVADA
```

Las llaves privadas nunca viajan. La del navegador se genera como no exportable.

### Cifrado asimétrico vs. hashing

|                  | Cifrado asimétrico (RSA-OAEP)              | Hashing (SHA-256, bcrypt, argon2)              |
| ---------------- | ------------------------------------------ | ---------------------------------------------- |
| ¿Reversible?     | Sí, con la llave privada                   | No, es de un solo sentido                      |
| ¿Llaves?         | Par pública/privada                        | Ninguna (las contraseñas llevan _salt_)        |
| ¿Para qué?       | Confidencialidad: solo el destinatario lee | Verificar sin revelar: contraseñas, integridad |
| En este proyecto | Mensajes del chat                          | Huella de las llaves públicas                  |

Regla práctica: si necesitas **recuperar** el dato, se cifra; si solo necesitas **comprobarlo**, se hashea. Por eso una contraseña nunca se cifra: se guarda su hash con un algoritmo lento (bcrypt/argon2) y, al iniciar sesión, se compara hash contra hash.

### Alcance de la demo

- El agente vive en el mismo proceso que el servidor. En un E2E real sería otro cliente y el servidor solo retransmitiría sobres que no puede abrir. El protocolo ya está diseñado así: la capa de transporte nunca maneja texto plano.
- No hay autenticación de llaves: un servidor malicioso podría sustituir la llave pública (ataque de intermediario). En producción se verifican las huellas o se firman las llaves.
- Las llaves viven en memoria: al recargar la página se generan de nuevo. En producción se guardarían en IndexedDB.
- Web Crypto solo funciona en contexto seguro (`https` o `localhost`).

## Elevator pitch: React Hooks (30 segundos)

> Los Hooks son funciones que permiten a un componente funcional "engancharse" a capacidades de React, como el estado y el ciclo de vida, sin escribir una clase. Existen porque las clases repartían una misma lógica entre varios métodos (`componentDidMount`, `componentDidUpdate`, `componentWillUnmount`), complicaban el `this` y hacían difícil reutilizar lógica con estado. Con Hooks el flujo es lineal: **estado → render → efecto**. `useState` guarda un dato y, al cambiarlo, React vuelve a renderizar; el render calcula la interfaz a partir de ese estado; y después `useEffect` sincroniza con el mundo exterior, por ejemplo abrir un socket, y su función de limpieza lo cierra al desmontar. En mi chat: llega un mensaje, actualizo el estado, React pinta la burbuja y un efecto baja el scroll. `useRef` completa el trío guardando lo que debe persistir sin provocar renders, como la conexión del socket o la llave privada.

## Estructura

```
server.js              Backend: transporte Socket.IO + agente simulado
shared/e2e.js          Cifrado E2E y hashing (mismo código en navegador y Node)
src/ChatWidget.jsx     Componente del chat (Hooks + Socket.IO client)
src/ChatWidget.css     Estilos del widget
src/main.jsx           Punto de entrada de React
test/smoke.test.js     Prueba de humo de extremo a extremo
```

# 9. CHECKLIST ANTES DE PUBLICAR

[✅] README explica el proyecto sin necesidad de revisar todo el detalle

[✅] Archivos organizados, sin pruebas sueltas o versiones viejas

[✅] Sin credenciales ni datos sensibles en el repositorio

[✅] Link a la fuente original incluido y funcionando

[✅] Proyecto publicado y accesible (repo, sitio en vivo, o prototipo interactivo segun corresponda)

[✅] Link compartido con tu coach
