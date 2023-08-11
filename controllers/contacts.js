import Contact from "../models/contact.js";
import { HttpError, ctrlWrapper } from "../helpers/index.js";

const getAll = async (req, res) => {
  const result = await Contact.find();
  console.log(Contact);
  res.json(result);
}

// const getById = async (req, res) => {
//   const { id } = req.params;
//   const result = await Contact.findById(id);
//   if (!result) {
//     throw HttpError(404, "Not found");
//   }
//   res.json(result);
// }

// const add = async(req, res) => {
//   const result = await Contact.create(req.body);
//   res.status(201).json(result);
// }

// const updateById = async (req, res) => {
//   const { id } = req.params;
//   const result = await Contact.findByIdAndUpdate(id, req.body, {new: true});
//   if (!result) { 
//     throw HttpError(404, "not found");
//   }
//   res.status(result);
// }

// const updateFavorite = async (req, res) => {
//   const { id } = req.params;
//   const result = await Contact.findByIdAndUpdate(id, req.body, {new: true});
//   if (!result) { 
//     throw HttpError(404, "not found");
//   }
//   res.status(result);
// }

// const deleteById = async (req, res) => {
//   const { id } = req.params;
//   const result = await Contact.findByIdAndRemove(id);
//   if (!result) {
//     throw HttpError(404, "Not found");
//   }
//   res.json({
//     message: "Delete success"
//   })
// }

console.log(Contact);

export default {
  getAll: ctrlWrapper(getAll),
  // getById: ctrlWrapper(getById),
  // add: ctrlWrapper(add),
  // updateById: ctrlWrapper(updateById),
  // updateFavorite: ctrlWrapper(updateFavorite),
  // deleteById: ctrlWrapper(deleteById),
};