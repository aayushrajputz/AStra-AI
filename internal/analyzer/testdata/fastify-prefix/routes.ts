function userRoutes(app) {
  app.get("/users", listUsers);
}

const fastify = Fastify();
fastify.register(userRoutes, { prefix: "/api" });
