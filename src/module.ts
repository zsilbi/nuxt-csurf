import { defu } from 'defu'
import { defineNuxtModule, createResolver, addServerHandler, addImports, addPlugin } from '@nuxt/kit'
import { RuntimeConfig } from '@nuxt/schema'

import type { ModuleOptions } from './types'

export * from './types'

export default defineNuxtModule<ModuleOptions>({
  meta: {
    name: 'nuxt-csurf',
    configKey: 'csurf'
  },
  defaults: {
    https: process.env.NODE_ENV === 'production',
    cookieKey: '',
    cookie: {
      path: '/',
      httpOnly: true,
      sameSite: 'strict'
    },
    methodsToProtect: ['POST', 'PUT', 'PATCH'],
    excludedUrls: [],
    encryptKey: undefined,
    encryptAlgorithm: "AES-CBC",
  },
  async setup(options, nuxt) {
    const { resolve } = createResolver(import.meta.url);

    if (!options.cookieKey) {
      options.cookieKey = `${options.https ? "__Host-" : ""}csrf`;
    }
    options.cookie = options.cookie || {}
    if (options.cookie.secure === undefined) {
      options.cookie.secure = !!options.https;
    }

    let algorithm = options.encryptAlgorithm;

    if (algorithm === undefined) {
      algorithm = "AES-CBC";

      options.encryptAlgorithm = algorithm;
    }

    if (options.encryptKey === undefined) {
      const { subtle } = globalThis.crypto;

      const encryptKey = await subtle.generateKey(
        {
          name: algorithm,
          length: 256,
        },
        true,
        ["encrypt", "decrypt"]
      );

      options.encryptKey = await subtle.exportKey("jwk", encryptKey);
    }

    nuxt.options.runtimeConfig.csurf = defu(nuxt.options.runtimeConfig.csurf, options as RuntimeConfig['csurf'])
    addServerHandler({ handler: resolve('runtime/server/middleware/csrf') })

    // Transpile runtime
    nuxt.options.build.transpile.push(resolve('runtime'))

    addImports(['useCsrf', 'useCsrfFetch'].map(key => ({
        name: key,
        as: key,
      from: resolve('runtime/composables')
    })))

    addPlugin(resolve('runtime/plugin'))
  }
})
