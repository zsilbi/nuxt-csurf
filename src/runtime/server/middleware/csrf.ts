
import { randomUUID, getRandomValues } from 'crypto'
import { defineEventHandler, getCookie, setCookie, getHeader, createError } from 'h3'
import { useRuntimeConfig } from '#imports'

const { subtle } = globalThis.crypto;
const csrfConfig = useRuntimeConfig().csurf

const importKey = async (key: JsonWebKey) => {
  return subtle.importKey(
    "jwk",
    key,
    {
      name: csrfConfig.encryptAlgorithm,
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
};

/**
 * Create a new CSRF token (encrypt secret using csrfConfig.encryptAlgorithm)
 */
const createCsrf = async (secret: string) => {
  const iv = getRandomValues(new Uint8Array(16));

  const encrypted = await subtle.encrypt(
    {
      name: csrfConfig.encryptAlgorithm,
      iv,
    },
    await importKey(csrfConfig.encryptKey),
    new TextEncoder().encode(secret)
  );

  const ivBase64 = Buffer.from(iv).toString("base64");
  const encryptedBase64 = Buffer.from(new Uint8Array(encrypted)).toString(
    "base64"
  );

  return ivBase64 + ":" + encryptedBase64;
};

/**
 * Check csrf token (decrypt secret using csrfConfig.encryptAlgorithm)
 */
const verifyCsrf = async (secret: string, token: string) => {
  const [iv, encrypted] = token.split(':')
  if (!iv || !encrypted) { return false }
  let decrypted
  try {
      const encodedDecrypted = await subtle.decrypt(
        {
          name: csrfConfig.encryptAlgorithm,
          iv: Buffer.from(iv, "base64"),
        },
        await importKey(csrfConfig.encryptKey),
        Buffer.from(encrypted, "base64")
      );
  
      decrypted = new TextDecoder().decode(encodedDecrypted);
    } catch (error) {
      return false;
    }
  
    return decrypted === secret;
  }

export default defineEventHandler(async (event) => {
  let secret = getCookie(event, csrfConfig.cookieKey)
  if (!secret) {
    secret = randomUUID()
    setCookie(event, csrfConfig.cookieKey, secret, csrfConfig.cookie)
  }

  Object.defineProperty(event.node.res, '_csrftoken', {
    value: await createCsrf(secret),
    enumerable: true
  })

  const method = event.node.req.method ?? ''
  if (!csrfConfig.methodsToProtect.includes(method)) { return }

  // verify the incoming csrf token
  const url = event.node.req.url ?? ''
  const excluded = csrfConfig.excludedUrls?.filter((el: string|[string, string]) =>
      Array.isArray(el) ? new RegExp(...el).test(url) : el === url
  ).length > 0
  const token = getHeader(event, 'csrf-token') ?? ''
  if (!excluded && !await verifyCsrf(secret, token)) {
    throw createError({
      statusCode: 403,
      name: 'EBADCSRFTOKEN',
      statusMessage: 'CSRF Token Mismatch'
    })
  }
})
