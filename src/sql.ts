import sqlite3InitModule from "@sqlite.org/sqlite-wasm";

const { capi, oo1, SQLite3Error } = await sqlite3InitModule();
const db = new oo1.DB(":memory:");
const dbPointer = db.pointer;
if (dbPointer === undefined) throw new Error("SQLite baza nije otvorena.");
db.exec(`
  CREATE TABLE notes (title TEXT, pin TEXT, owner TEXT, message TEXT);
  INSERT INTO notes VALUES
    ('Podsjetnik', '2468', 'Ana', 'Rezerviraj dvoranu za petak.'),
    ('Plan puta', '3179', 'Luka', 'Polazak vlaka je u 07:35.'),
    ('Nacrt', '5831', 'Mia', 'Prva verzija projekta čeka pregled.');
  PRAGMA query_only = ON;
`);

let selects = 0;

db.checkRc(capi.sqlite3_set_authorizer(dbPointer, (_context, action, table, _column, database) => {
  if (action === capi.SQLITE_SELECT && ++selects === 1) return capi.SQLITE_OK;
  if (action === capi.SQLITE_READ && table === "notes" && database === "main") {
    return capi.SQLITE_OK;
  }
  return capi.SQLITE_DENY;
}, 0));

const selectNotes = "SELECT title, owner, message FROM notes WHERE";
const parameterizedQuery = `${selectNotes} title = ? AND pin = ?`;

export const attackTitle = "' OR 1=1 --";

export function queryNotes(title: string, pin: string, vulnerable: boolean) {
  selects = 0;
  if (vulnerable) {
    const query = `${selectNotes} title = '${title}' AND pin = '${pin}'`;
    try {
      return { query, notes: db.selectObjects(query) };
    } catch (error) {
      if (!(error instanceof SQLite3Error)) throw error;
      return { query, error: "SQLite je odbio upit." };
    }
  }

  return { query: parameterizedQuery, notes: db.selectObjects(parameterizedQuery, [title, pin]) };
}
