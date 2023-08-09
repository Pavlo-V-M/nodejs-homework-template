import fs from "fs/promises";
import path from "path";
import { nanoid } from "nanoid";

// Отримуємо данні із файлу contacts.json.
// Створюємо абсолютний шлях до файлу із даними, які треба обробити.
const contactsPath = path.resolve("models", "contacts.json");

const updateContacts = contacts => {
	return fs.writeFile(contactsPath, JSON.stringify(contacts, null, 2));
};

// Створюємо методи обробки данних.
const listContacts = async () => {
  const data = await fs.readFile(contactsPath);
  return JSON.parse(data);
}

// const getContactById = async (contactId) => {
//   const contacts = await listContacts();
//   const result = contacts.find(item => item.id === contactId);
//   return result || null;
// }

// const removeContact = async (contactId) => {
//   const contacts = await listContacts();
//   const index = contacts.findIndex((item) => item.id === contactId);
//   if (index === -1) { 
//     return null;
//   };
//   const [result] = contacts.splice(index, 1);
//   // await fs.writeFile(contactsPath, JSON.stringify(contacts, null, 2));
//   await updateContacts(contacts);
//   return result || null;
// }

const addContact = async (body) => {
  const contacts = await listContacts();
  const newContact = {
    id: nanoid(),
    ... body
  }
  contacts.push(newContact);
  // await fs.readFile(contactsPath, JSON.stringify(contacts, null, 2));
  await updateContacts(contacts);
  return newContact;
}

// const updateContact = async(contactId, {name, email, phone}) => {
//   const contacts = await listContacts();
//   const index = contacts.findIndex(item => item.id === contactId);
//   if (index === -1) { 
//     return null;
//   }
//   contacts[index] = { id: contactId, name, email, phone };
//   // await fs.writeFile(contactsPath, JSON.stringify(contacts, null, 2));
//   await updateContacts(contacts);
//   return contacts[index];
// }

// Створюємо достуність методів обробки данних в інших файлах
export default {
  listContacts,
  // getContactById,
  // removeContact,
  addContact,
  // updateContact,
};
