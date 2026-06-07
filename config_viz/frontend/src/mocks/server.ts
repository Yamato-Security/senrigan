import { setupServer } from "msw/node";
import { handlers } from "./handlers";

/** MSW server for Node.js / Vitest environment */
export const server = setupServer(...handlers);

