export function validateRequest(schema) {
  return function (req, res, next) {
    schema.parse({ body: req.body });
    next();
  };
}
