// Bus sender names that no HTTP caller may ever claim. Kept in its own module so
// the message route can reserve them without importing the questions store.

/** Bus sender of an owner answer given in the dashboard UI (the answer node uses it; HTTP may never claim it). */
export const OWNER_UI_SENDER = 'owner-ui'
