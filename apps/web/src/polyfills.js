// torvex web - buffer polyfill for browser
// must import before any crypto libs that need Buffer

import { Buffer } from "buffer";
globalThis.Buffer = Buffer;
